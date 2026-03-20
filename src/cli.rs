use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Ironlock - A secure file encryption tool
///
/// Encrypts files using Argon2id for key derivation and ChaCha20-Poly1305 for
/// authenticated encryption. Your files are protected with military-grade security.
#[derive(Parser, Debug)]
#[command(name = "ironlock")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt one or more files
    ///
    /// Fields will be encrypted and saved with the .il extension.
    /// Original files are preserved (not deleted).
    /// If no files are specified, reads from stdin and writes to stdout.
    #[command(visible_alias = "enc", visible_alias = "e")]
    Encrypt {
        /// Files to encrypt (reads from stdin if omitted)
        #[arg(num_args = 0..)]
        files: Vec<PathBuf>,

        /// Force overwrite without prompting if output file exists
        #[arg(short, long, default_value_t = false)]
        force: bool,

        /// Securely delete original files after encryption (overwrites with random data)
        #[arg(short = 's', long, visible_alias = "delete", default_value_t = false)]
        shred: bool,

        /// Show a progress bar when processing multiple files
        #[arg(short, long, default_value_t = false)]
        progress: bool,
    },

    /// Decrypt one or more .il files
    ///
    /// Files will be decrypted and restored to their original format.
    /// If no files are specified, reads from stdin and writes to stdout.
    #[command(visible_alias = "dec", visible_alias = "d")]
    Decrypt {
        /// Files to decrypt (reads from stdin if omitted)
        #[arg(num_args = 0..)]
        files: Vec<PathBuf>,

        /// Output directory for decrypted files (defaults to current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Force overwrite without prompting if output file exists
        #[arg(short, long, default_value_t = false)]
        force: bool,

        /// Show a progress bar when processing multiple files
        #[arg(short, long, default_value_t = false)]
        progress: bool,
    },
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    // ==================== Basic Parsing Tests ====================

    #[test]
    fn test_cli_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_encrypt_single_file() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt {
                files,
                force,
                shred,
                progress,
            } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0], PathBuf::from("file.txt"));
                assert!(!force);
                assert!(!shred);
                assert!(!progress);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_multiple_files() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "a.txt", "b.pdf", "c.doc"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, force, .. } => {
                assert_eq!(files.len(), 3);
                assert_eq!(files[0], PathBuf::from("a.txt"));
                assert_eq!(files[1], PathBuf::from("b.pdf"));
                assert_eq!(files[2], PathBuf::from("c.doc"));
                assert!(!force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_force_short() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "-f", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, force, .. } => {
                assert_eq!(files.len(), 1);
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_force_long() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "--force", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { force, shred, .. } => {
                assert!(force);
                assert!(!shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_single_file() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt", "file.il"]).unwrap();

        match cli.command {
            Commands::Decrypt {
                files,
                output,
                force,
                progress,
            } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0], PathBuf::from("file.il"));
                assert!(output.is_none());
                assert!(!force);
                assert!(!progress);
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_output_short() {
        let cli =
            Cli::try_parse_from(["ironlock", "decrypt", "file.il", "-o", "./output/"]).unwrap();

        match cli.command {
            Commands::Decrypt { output, .. } => {
                assert_eq!(output, Some(PathBuf::from("./output/")));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_output_long() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt", "file.il", "--output", "/tmp/out"])
            .unwrap();

        match cli.command {
            Commands::Decrypt { output, .. } => {
                assert_eq!(output, Some(PathBuf::from("/tmp/out")));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_force_and_output() {
        let cli = Cli::try_parse_from([
            "ironlock", "decrypt", "a.il", "b.il", "-o", "./out", "--force",
        ])
        .unwrap();

        match cli.command {
            Commands::Decrypt {
                files,
                output,
                force,
                ..
            } => {
                assert_eq!(files.len(), 2);
                assert_eq!(output, Some(PathBuf::from("./out")));
                assert!(force);
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    // ==================== Alias Tests ====================

    #[test]
    fn test_encrypt_alias_enc() {
        let cli = Cli::try_parse_from(["ironlock", "enc", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_alias_e() {
        let cli = Cli::try_parse_from(["ironlock", "e", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_alias_dec() {
        let cli = Cli::try_parse_from(["ironlock", "dec", "file.il"]).unwrap();

        match cli.command {
            Commands::Decrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.il"));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_alias_d() {
        let cli = Cli::try_parse_from(["ironlock", "d", "file.il"]).unwrap();

        match cli.command {
            Commands::Decrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.il"));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    // ==================== Error Cases ====================

    #[test]
    fn test_encrypt_no_files_is_valid() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt"]).unwrap();
        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert!(files.is_empty());
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_no_files_is_valid() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt"]).unwrap();
        match cli.command {
            Commands::Decrypt { files, .. } => {
                assert!(files.is_empty());
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_unknown_command_fails() {
        let result = Cli::try_parse_from(["ironlock", "unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_command_fails() {
        let result = Cli::try_parse_from(["ironlock"]);
        assert!(result.is_err());
    }

    // ==================== Path Handling Tests ====================

    #[test]
    fn test_absolute_path() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "/home/user/secret.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("/home/user/secret.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_relative_path_with_dots() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "../parent/file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("../parent/file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_path_with_spaces() {
        let cli =
            Cli::try_parse_from(["ironlock", "encrypt", "path with spaces/file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("path with spaces/file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    // ==================== Shred Flag Tests ====================

    #[test]
    fn test_encrypt_with_shred_short() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "-s", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { shred, .. } => {
                assert!(shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_shred_long() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "--shred", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { shred, .. } => {
                assert!(shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_delete_alias() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "--delete", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { shred, .. } => {
                assert!(shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_shred_defaults_to_false() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { shred, .. } => {
                assert!(!shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_shred_and_force() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "-f", "-s", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { force, shred, .. } => {
                assert!(force);
                assert!(shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    // ==================== Progress Flag Tests ====================

    #[test]
    fn test_encrypt_with_progress_short() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "-p", "file.txt"]).unwrap();
        match cli.command {
            Commands::Encrypt { progress, .. } => assert!(progress),
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_progress_long() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "--progress", "file.txt"]).unwrap();
        match cli.command {
            Commands::Encrypt { progress, .. } => assert!(progress),
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_progress() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt", "--progress", "file.il"]).unwrap();
        match cli.command {
            Commands::Decrypt { progress, .. } => assert!(progress),
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_progress_defaults_to_false() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "file.txt"]).unwrap();
        match cli.command {
            Commands::Encrypt { progress, .. } => assert!(!progress),
            _ => panic!("Expected Encrypt command"),
        }
    }

    // ==================== Mixed Flag Tests ====================

    #[test]
    fn test_mixed_flags_and_files() {
        // Force flag before files
        let cli1 = Cli::try_parse_from(["ironlock", "encrypt", "-f", "a.txt", "b.txt"]).unwrap();
        match cli1.command {
            Commands::Encrypt { files, force, .. } => {
                assert_eq!(files.len(), 2);
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }

        // Force flag after files
        let cli2 = Cli::try_parse_from(["ironlock", "encrypt", "a.txt", "b.txt", "-f"]).unwrap();
        match cli2.command {
            Commands::Encrypt { files, force, .. } => {
                assert_eq!(files.len(), 2);
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }
}
