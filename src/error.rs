use thiserror::Error;

#[derive(Error, Debug)]
pub enum IronlockError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Invalid file extension: expected .il for decryption")]
    InvalidExtension,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: incorrect password or corrupted file")]
    DecryptionFailed,

    #[error("Invalid file format: not a valid Ironlock encrypted file")]
    InvalidFileFormat,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Passwords do not match")]
    PasswordMismatch,

    #[error("Password cannot be empty")]
    EmptyPassword,

    #[error("Secure deletion failed: {0}")]
    SecureDeletionFailed(String),

    #[error("Not a directory: {0}")]
    NotADirectory(String),

    #[error("Operation cancelled by user")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, IronlockError>;
