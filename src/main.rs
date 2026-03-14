mod cli;
mod crypto;
mod error;
mod file_ops;
mod memlock;

use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

use colored::Colorize;
use zeroize::Zeroizing;

use cli::{Cli, Commands};
use error::{LockboxError, Result};
use file_ops::{decrypt_directory, decrypt_file_to_path, encrypt_directory, encrypt_file};
use memlock::mlock_slice;

/// Prompt for password input (hidden from terminal)
fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{}", prompt);
    io::stderr().flush()?;

    let password =
        rpassword::read_password().map_err(|e| LockboxError::IoError(io::Error::other(e)))?;

    // Best-effort mlock to prevent the password from being swapped to disk.
    mlock_slice(password.as_bytes());

    Ok(Zeroizing::new(password))
}

/// Prompt for password with confirmation (for encryption)
fn prompt_password_with_confirm() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;

    if password.is_empty() {
        return Err(LockboxError::EmptyPassword);
    }

    let confirm = prompt_password("Confirm password: ")?;

    if *password != *confirm {
        return Err(LockboxError::PasswordMismatch);
    }

    Ok(password)
}

/// Prompt for password (for decryption - no confirmation needed)
fn prompt_password_decrypt() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;

    if password.is_empty() {
        return Err(LockboxError::EmptyPassword);
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

/// Tracks per-file operation results
struct Counters {
    success: usize,
    errors: usize,
    skipped: usize,
}

impl Counters {
    fn new() -> Self {
        Self {
            success: 0,
            errors: 0,
            skipped: 0,
        }
    }

    /// Handle a single operation result, printing the outcome
    fn handle_result(&mut self, result: std::result::Result<PathBuf, LockboxError>, shred: bool) {
        match result {
            Ok(output_path) => {
                if shred {
                    println!(
                        "{} → {} (original securely deleted)",
                        "✓".green(),
                        output_path.display()
                    );
                } else {
                    println!("{} → {}", "✓".green(), output_path.display());
                }
                self.success += 1;
            }
            Err(LockboxError::Cancelled) => {
                println!("{}", "skipped".yellow());
                self.skipped += 1;
            }
            Err(LockboxError::DecryptionFailed) => {
                println!("{} incorrect password or corrupted file", "✗".red());
                self.errors += 1;
            }
            Err(e) => {
                println!("{} {}", "✗".red(), e);
                self.errors += 1;
            }
        }
    }

    /// Print the final summary line
    fn print_summary(&self, operation: &str) {
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
        } => {
            if files.is_empty() {
                require_piped_stdin();
                let password = prompt_password_with_confirm()?;
                eprintln!();
                encrypt_stdin(password.as_bytes())?;
            } else {
                println!("{}", "🔐 Lockbox Encryption".cyan().bold());
                println!();

                let password = prompt_password_with_confirm()?;
                println!();

                let mut counters = Counters::new();

                for file_path in &files {
                    if file_path.is_dir() {
                        println!("Encrypting directory {} ...", file_path.display());
                        match encrypt_directory(file_path, password.as_bytes(), force, shred) {
                            Ok(results) => {
                                for (source, result) in results {
                                    print!("  Encrypting {} ... ", source.display());
                                    io::stdout().flush()?;
                                    counters.handle_result(result, shred);
                                }
                            }
                            Err(e) => {
                                println!("{} {}", "✗".red(), e);
                                counters.errors += 1;
                            }
                        }
                    } else {
                        print!("Encrypting {} ... ", file_path.display());
                        io::stdout().flush()?;
                        let result = encrypt_file(file_path, password.as_bytes(), force, shred);
                        counters.handle_result(result, shred);
                    }
                }

                counters.print_summary("encrypted");
            }
        }
        Commands::Decrypt {
            files,
            output,
            force,
        } => {
            if files.is_empty() {
                require_piped_stdin();
                let password = prompt_password_decrypt()?;
                eprintln!();
                decrypt_stdin(password.as_bytes())?;
            } else {
                println!("{}", "🔓 Lockbox Decryption".cyan().bold());
                println!();

                let password = prompt_password_decrypt()?;
                println!();

                let mut counters = Counters::new();

                for file_path in &files {
                    if file_path.is_dir() {
                        println!("Decrypting directory {} ...", file_path.display());
                        match decrypt_directory(
                            file_path,
                            password.as_bytes(),
                            output.as_deref(),
                            force,
                        ) {
                            Ok(results) => {
                                for (source, result) in results {
                                    print!("  Decrypting {} ... ", source.display());
                                    io::stdout().flush()?;
                                    counters.handle_result(result, false);
                                }
                            }
                            Err(e) => {
                                println!("{} {}", "✗".red(), e);
                                counters.errors += 1;
                            }
                        }
                    } else {
                        print!("Decrypting {} ... ", file_path.display());
                        io::stdout().flush()?;
                        let result = decrypt_file_to_path(
                            file_path,
                            password.as_bytes(),
                            output.as_deref(),
                            force,
                        );
                        counters.handle_result(result, false);
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
