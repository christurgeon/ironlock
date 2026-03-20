mod cli;
mod crypto;
mod error;
mod file_ops;
mod memlock;

use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use zeroize::Zeroizing;

use cli::{Cli, Commands};
use error::{IronlockError, Result};
use file_ops::{collect_files_recursive, decrypt_file_to_path, encrypt_file, IRONLOCK_EXTENSION};
use memlock::mlock_slice;

/// Prompt for password input (hidden from terminal)
fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{}", prompt);
    io::stderr().flush()?;

    let password =
        rpassword::read_password().map_err(|e| IronlockError::IoError(io::Error::other(e)))?;

    // Best-effort mlock to prevent the password from being swapped to disk.
    mlock_slice(password.as_bytes());

    Ok(Zeroizing::new(password))
}

/// Prompt for password with confirmation (for encryption)
fn prompt_password_with_confirm() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;

    if password.is_empty() {
        return Err(IronlockError::EmptyPassword);
    }

    let confirm = prompt_password("Confirm password: ")?;

    if *password != *confirm {
        return Err(IronlockError::PasswordMismatch);
    }

    Ok(password)
}

/// Prompt for password (for decryption - no confirmation needed)
fn prompt_password_decrypt() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;

    if password.is_empty() {
        return Err(IronlockError::EmptyPassword);
    }

    Ok(password)
}

/// Encrypt data read from stdin and write the encrypted blob to stdout
fn encrypt_stdin(password: &[u8]) -> Result<()> {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    let encrypted = crypto::create_encrypted_file(password, "stdin", &data)?;
    io::stdout().write_all(&encrypted)?;
    Ok(())
}

/// Decrypt data read from stdin and write the plaintext to stdout
fn decrypt_stdin(password: &[u8]) -> Result<()> {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    let (_filename, plaintext) = crypto::decrypt_file(password, &data)?;
    io::stdout().write_all(&plaintext)?;
    Ok(())
}

/// Checks that stdin is piped (not a terminal) when no files are provided.
/// Exits with an error message if stdin is a terminal.
fn require_piped_stdin() {
    if io::stdin().is_terminal() {
        eprintln!(
            "{} No files specified. Pipe data to stdin or provide file paths.",
            "Error:".red().bold()
        );
        std::process::exit(1);
    }
}

/// Count total files for progress bar (expanding directories)
fn count_files(files: &[PathBuf], filter_lb: bool) -> u64 {
    let mut count: u64 = 0;
    for path in files {
        if path.is_dir() {
            if let Ok(dir_files) = collect_files_recursive(path) {
                if filter_lb {
                    count += dir_files
                        .iter()
                        .filter(|f| {
                            f.extension().and_then(|e| e.to_str()) == Some(IRONLOCK_EXTENSION)
                        })
                        .count() as u64;
                } else {
                    count += dir_files.len() as u64;
                }
            } else {
                count += 1; // will error during processing
            }
        } else {
            count += 1;
        }
    }
    count
}

/// Creates a styled progress bar
fn make_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("=> "),
    );
    pb
}

/// Tracks per-file operation results and optionally displays a progress bar
struct Counters {
    success: usize,
    errors: usize,
    skipped: usize,
    pb: Option<ProgressBar>,
}

impl Counters {
    fn new(pb: Option<ProgressBar>) -> Self {
        Self {
            success: 0,
            errors: 0,
            skipped: 0,
            pb,
        }
    }

    /// Output a line — through the progress bar if active, otherwise println
    fn output(&self, msg: &str) {
        match &self.pb {
            Some(pb) => pb.println(msg),
            None => println!("{}", msg),
        }
    }

    /// Handle a single operation result, printing the outcome.
    /// `prefix` is the "Encrypting foo ... " text.
    fn handle_result(
        &mut self,
        prefix: &str,
        result: std::result::Result<PathBuf, IronlockError>,
        shred: bool,
    ) {
        let suffix = match &result {
            Ok(output_path) => {
                if shred {
                    format!(
                        "{} → {} (original securely deleted)",
                        "✓".green(),
                        output_path.display()
                    )
                } else {
                    format!("{} → {}", "✓".green(), output_path.display())
                }
            }
            Err(IronlockError::Cancelled) => format!("{}", "skipped".yellow()),
            Err(IronlockError::DecryptionFailed) => {
                format!("{} incorrect password or corrupted file", "✗".red())
            }
            Err(e) => format!("{} {}", "✗".red(), e),
        };

        self.output(&format!("{}{}", prefix, suffix));

        match &result {
            Ok(_) => self.success += 1,
            Err(IronlockError::Cancelled) => self.skipped += 1,
            Err(_) => self.errors += 1,
        }

        if let Some(ref pb) = self.pb {
            pb.inc(1);
        }
    }

    /// Handle a directory-level error
    fn handle_dir_error(&mut self, e: IronlockError) {
        self.output(&format!("{} {}", "✗".red(), e));
        self.errors += 1;
    }

    /// Print the final summary line
    fn print_summary(&self, operation: &str) {
        if let Some(ref pb) = self.pb {
            pb.finish_and_clear();
        }
        println!();
        if self.errors == 0 && self.skipped == 0 {
            println!(
                "{} {} file(s) {} successfully",
                "✓".green(),
                self.success,
                operation,
            );
        } else {
            println!(
                "{} {} succeeded, {} failed, {} skipped",
                "⚠".yellow(),
                self.success,
                self.errors,
                self.skipped
            );
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Commands::Encrypt {
            files,
            force,
            shred,
            progress,
        } => {
            if files.is_empty() {
                require_piped_stdin();
                let password = prompt_password_with_confirm()?;
                eprintln!();
                encrypt_stdin(password.as_bytes())?;
            } else {
                println!("{}", "🔐 Ironlock Encryption".cyan().bold());
                println!();

                let password = prompt_password_with_confirm()?;
                println!();

                let pb = if progress {
                    Some(make_progress_bar(count_files(&files, false)))
                } else {
                    None
                };
                let mut counters = Counters::new(pb);

                for file_path in &files {
                    if file_path.is_dir() {
                        counters
                            .output(&format!("Encrypting directory {} ...", file_path.display()));
                        match collect_files_recursive(file_path) {
                            Ok(dir_files) => {
                                for source in dir_files {
                                    let prefix = format!("  Encrypting {} ... ", source.display());
                                    let result =
                                        encrypt_file(&source, password.as_bytes(), force, shred);
                                    counters.handle_result(&prefix, result, shred);
                                }
                            }
                            Err(e) => counters.handle_dir_error(e),
                        }
                    } else {
                        let prefix = format!("Encrypting {} ... ", file_path.display());
                        let result = encrypt_file(file_path, password.as_bytes(), force, shred);
                        counters.handle_result(&prefix, result, shred);
                    }
                }

                counters.print_summary("encrypted");
            }
        }
        Commands::Decrypt {
            files,
            output,
            force,
            progress,
        } => {
            if files.is_empty() {
                require_piped_stdin();
                let password = prompt_password_decrypt()?;
                eprintln!();
                decrypt_stdin(password.as_bytes())?;
            } else {
                println!("{}", "🔓 Ironlock Decryption".cyan().bold());
                println!();

                let password = prompt_password_decrypt()?;
                println!();

                let pb = if progress {
                    Some(make_progress_bar(count_files(&files, true)))
                } else {
                    None
                };
                let mut counters = Counters::new(pb);

                for file_path in &files {
                    if file_path.is_dir() {
                        counters
                            .output(&format!("Decrypting directory {} ...", file_path.display()));
                        match collect_files_recursive(file_path) {
                            Ok(dir_files) => {
                                for source in dir_files {
                                    if source.extension().and_then(|e| e.to_str())
                                        != Some(IRONLOCK_EXTENSION)
                                    {
                                        continue;
                                    }
                                    // Compute output dir preserving directory structure
                                    let relative =
                                        source.strip_prefix(file_path).unwrap_or(&source);
                                    let target_dir = match &output {
                                        Some(base) => {
                                            base.join(relative.parent().unwrap_or(Path::new("")))
                                        }
                                        None => {
                                            source.parent().unwrap_or(Path::new("")).to_path_buf()
                                        }
                                    };
                                    let prefix = format!("  Decrypting {} ... ", source.display());
                                    let result = decrypt_file_to_path(
                                        &source,
                                        password.as_bytes(),
                                        Some(&target_dir),
                                        force,
                                    );
                                    counters.handle_result(&prefix, result, false);
                                }
                            }
                            Err(e) => counters.handle_dir_error(e),
                        }
                    } else {
                        let prefix = format!("Decrypting {} ... ", file_path.display());
                        let result = decrypt_file_to_path(
                            file_path,
                            password.as_bytes(),
                            output.as_deref(),
                            force,
                        );
                        counters.handle_result(&prefix, result, false);
                    }
                }

                counters.print_summary("decrypted");
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{} {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}
