use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{LockboxError, Result};
use crate::memlock::mlock_slice;

/// Lockbox file format magic bytes - indentifies our encrypted files
pub const MAGIC_BYTES: &[u8; 8] = b"LOCKBOX\x01";

/// Version of the file format (for future compatibility)
pub const FORMAT_VERSION: u8 = 2;

/// Salt length for Argon2id (16 bytes = 128 bits, recommended minimum)
pub const SALT_LENGTH: usize = 16;

/// Nonce length for ChaCha20-Poly1305 (12 bytes = 96 bits, standard)
pub const NONCE_LENGTH: usize = 12;

/// Key length for ChaCha20-Poly1305 (32 bytes = 256 bits)
pub const KEY_LENGTH: usize = 32;

/// Argon2id parameters - tuned for security
/// These parameters provide strong resistance against GPU/ASIC attacks
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 4
const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Argon2id key derivation parameters stored in the file header (v2+)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Returns the current default (strongest) parameters for new encryptions
    pub fn current() -> Self {
        Self {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
        }
    }
}

/// Derives a 256-bit encryption key from a password using Argon2id
///
/// Argon2id is the recommended password hashing algorithm, combining:
/// - Argon2i: resistance against side-channel attacks
/// - Argon2d: resistance against GPU cracking attacks
///
/// The salt ensures that the same password produces different keys for different files.
///
/// The derived key is memory-locked (best-effort) to prevent it from being swapped to disk.
/// Callers should be aware that the returned key occupies mlocked memory.
pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
    kdf_params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    let params = Params::new(
        kdf_params.memory_kib,
        kdf_params.iterations,
        kdf_params.parallelism,
        Some(KEY_LENGTH),
    )
    .map_err(|e| LockboxError::EncryptionFailed(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| LockboxError::EncryptionFailed(format!("Key derivation failed: {}", e)))?;

    // Best-effort mlock to prevent the key from being swapped to disk.
    // Failures are silently ignored (e.g., due to RLIMIT_MEMLOCK).
    mlock_slice(key.as_ref());

    Ok(key)
}

/// Generates a cryptographically secure random salt
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generates a cryptographically secure random nonce
pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypts plaintext data using ChaCha20-Poly1305
///
/// ChaCha20-Poly1305 is an authenticated encryption algorithm that provides:
/// - Confidentiality: data is encrypted with ChaCha20 stream cipher
/// - Integrity: Poly1305 MAC ensures that data hasn't been tampered with
/// - Authentication: verifies the cipher text was created with the correct key
///
/// Returns the ciphertext with the 16-byte authentication tag appended.
pub fn encrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| LockboxError::EncryptionFailed(format!("Cipher init failed: {}", e)))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| LockboxError::EncryptionFailed(format!("Encryption failed: {}", e)))
}

/// Decrypts ciphertext using ChaCha20-Poly1305
///
/// This function also verifies the authentication tag, ensuring:
/// - The data hasn't been modified
/// - The correct password was used
///
/// Returns an error if authentication fails (wrong password or corrupted data).
pub fn decrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| LockboxError::DecryptionFailed)?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| LockboxError::DecryptionFailed)
}

// Encrypted file structure:
//
// Version 1 (legacy):
// | Offset | Size | Description                          |
// |--------|------|--------------------------------------|
// | 0      | 8    | Magic bytes "LOCKBOX\x01"            |
// | 8      | 1    | Format version (1)                   |
// | 9      | 2    | Original filename length (u16 BE)    |
// | 11     | N    | Original filename (UTF-8)            |
// | 11+N   | 16   | Argon2id salt                        |
// | 27+N   | 12   | ChaCha20 nonce                       |
// | 39+N   | ...  | Encrypted data + auth tag (16 bytes) |
//
// Version 2 (current):
// | Offset | Size | Description                          |
// |--------|------|--------------------------------------|
// | 0      | 8    | Magic bytes "LOCKBOX\x01"            |
// | 8      | 1    | Format version (2)                   |
// | 9      | 4    | Argon2 memory cost (u32 BE, in KiB)  |
// | 13     | 4    | Argon2 iterations (u32 BE)           |
// | 17     | 4    | Argon2 parallelism (u32 BE)          |
// | 21     | 2    | Original filename length (u16 BE)    |
// | 23     | N    | Original filename (UTF-8)            |
// | 23+N   | 16   | Argon2id salt                        |
// | 39+N   | 12   | ChaCha20 nonce                       |
// | 51+N   | ...  | Encrypted data + auth tag (16 bytes) |

/// Creates the encrypted file format with all metadata using default KDF params
pub fn create_encrypted_file(
    password: &[u8],
    original_filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    create_encrypted_file_with_params(
        password,
        original_filename,
        plaintext,
        &KdfParams::current(),
    )
}

/// Creates the encrypted file format with all metadata using the specified KDF params
pub fn create_encrypted_file_with_params(
    password: &[u8],
    original_filename: &str,
    plaintext: &[u8],
    kdf_params: &KdfParams,
) -> Result<Vec<u8>> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let key = derive_key_from_password(password, &salt, kdf_params)?;
    let ciphertext = encrypt(&key, &nonce, plaintext)?;

    // Build the file structure
    let filename_bytes = original_filename.as_bytes();
    if filename_bytes.len() > u16::MAX as usize {
        return Err(LockboxError::EncryptionFailed(
            "Filename too long (exceeds 65535 bytes)".to_string(),
        ));
    }
    let filename_len = filename_bytes.len() as u16;
    let mut output = Vec::with_capacity(
        MAGIC_BYTES.len()
            + 1 // version
            + 4 // memory cost
            + 4 // iterations
            + 4 // parallelism
            + 2 // filename length
            + filename_bytes.len()
            + SALT_LENGTH
            + NONCE_LENGTH
            + ciphertext.len(),
    );

    // Write header
    output.extend_from_slice(MAGIC_BYTES);
    output.push(FORMAT_VERSION);
    output.extend_from_slice(&kdf_params.memory_kib.to_be_bytes());
    output.extend_from_slice(&kdf_params.iterations.to_be_bytes());
    output.extend_from_slice(&kdf_params.parallelism.to_be_bytes());
    output.extend_from_slice(&filename_len.to_be_bytes());
    output.extend_from_slice(filename_bytes);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Parses an encrypted file and decrypts its contents
///
/// Supports both version 1 (legacy) and version 2 (current) file formats.
/// - Version 1: uses hardcoded KDF params (64 MiB, 3 iterations, 4 parallelism)
/// - Version 2: reads KDF params from the file header
///
/// Returns: (original_filename, decrypted_data)
pub fn decrypt_file(password: &[u8], encrypted_data: &[u8]) -> Result<(String, Vec<u8>)> {
    // Minimum size for v1: magic(8) + version(1) + filename_len(2) + salt(16) + nonce(12) + tag(16) = 55
    const MINIMUM_SIZE_V1: usize = 8 + 1 + 2 + 16 + 12 + 16;
    // Minimum size for v2: magic(8) + version(1) + kdf(12) + filename_len(2) + salt(16) + nonce(12) + tag(16) = 67
    const MINIMUM_SIZE_V2: usize = 8 + 1 + 12 + 2 + 16 + 12 + 16;

    if encrypted_data.len() < MINIMUM_SIZE_V1 {
        return Err(LockboxError::InvalidFileFormat);
    }

    // Verify magic bytes
    if &encrypted_data[0..8] != MAGIC_BYTES {
        return Err(LockboxError::InvalidFileFormat);
    }

    // Check version
    let version = encrypted_data[8];

    let (kdf_params, filename_len_offset) = match version {
        1 => {
            // Version 1: use hardcoded v1 params
            let kdf = KdfParams {
                memory_kib: ARGON2_MEMORY_KIB,
                iterations: ARGON2_ITERATIONS,
                parallelism: ARGON2_PARALLELISM,
            };
            (kdf, 9usize)
        }
        2 => {
            // Version 2: read KDF params from header
            if encrypted_data.len() < MINIMUM_SIZE_V2 {
                return Err(LockboxError::InvalidFileFormat);
            }
            let memory_kib = u32::from_be_bytes(
                encrypted_data[9..13]
                    .try_into()
                    .map_err(|_| LockboxError::InvalidFileFormat)?,
            );
            let iterations = u32::from_be_bytes(
                encrypted_data[13..17]
                    .try_into()
                    .map_err(|_| LockboxError::InvalidFileFormat)?,
            );
            let parallelism = u32::from_be_bytes(
                encrypted_data[17..21]
                    .try_into()
                    .map_err(|_| LockboxError::InvalidFileFormat)?,
            );
            let kdf = KdfParams {
                memory_kib,
                iterations,
                parallelism,
            };
            (kdf, 21usize)
        }
        _ => return Err(LockboxError::InvalidFileFormat),
    };

    // Read filename length
    let filename_len = u16::from_be_bytes([
        encrypted_data[filename_len_offset],
        encrypted_data[filename_len_offset + 1],
    ]) as usize;

    // Calculate offsets
    let filename_start = filename_len_offset + 2;
    let filename_end = filename_start + filename_len;
    let salt_start = filename_end;
    let salt_end = salt_start + SALT_LENGTH;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + NONCE_LENGTH;
    let ciphertext_start = nonce_end;

    // Validate file size
    if encrypted_data.len() < ciphertext_start + 16 {
        return Err(LockboxError::InvalidFileFormat);
    }

    // Extract components
    let filename_bytes = &encrypted_data[filename_start..filename_end];
    let original_filename =
        String::from_utf8(filename_bytes.to_vec()).map_err(|_| LockboxError::InvalidFileFormat)?;

    let salt: [u8; SALT_LENGTH] = encrypted_data[salt_start..salt_end]
        .try_into()
        .map_err(|_| LockboxError::InvalidFileFormat)?;

    let nonce: [u8; NONCE_LENGTH] = encrypted_data[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| LockboxError::InvalidFileFormat)?;

    let ciphertext = &encrypted_data[ciphertext_start..];

    // Derive key and decrypt
    let key = derive_key_from_password(password, &salt, &kdf_params)?;
    let plaintext = decrypt(&key, &nonce, ciphertext)?;

    Ok((original_filename, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Key Derivation Tests ====================

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password";
        let salt = [0u8; SALT_LENGTH];

        let key1 = derive_key_from_password(password, &salt, &KdfParams::current()).unwrap();
        let key2 = derive_key_from_password(password, &salt, &KdfParams::current()).unwrap();

        assert_eq!(
            *key1, *key2,
            "Same password and salt should produce same key"
        );
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = b"test_password";
        let salt1 = [0u8; SALT_LENGTH];
        let salt2 = [1u8; SALT_LENGTH];

        let key1 = derive_key_from_password(password, &salt1, &KdfParams::current()).unwrap();
        let key2 = derive_key_from_password(password, &salt2, &KdfParams::current()).unwrap();

        assert_ne!(
            *key1, *key2,
            "Different salts should produce different keys"
        );
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = [0u8; SALT_LENGTH];
        let key1 = derive_key_from_password(b"password1", &salt, &KdfParams::current()).unwrap();
        let key2 = derive_key_from_password(b"password2", &salt, &KdfParams::current()).unwrap();

        assert_ne!(
            *key1, *key2,
            "Different passwords should produce different keys"
        );
    }

    #[test]
    fn test_derive_key_empty_password() {
        let salt = [0u8; SALT_LENGTH];
        let result = derive_key_from_password(b"", &salt, &KdfParams::current());
        assert!(result.is_ok(), "Empty password should still derive a key");
    }

    #[test]
    fn test_derive_key_length() {
        let password = b"test";
        let salt = [0u8; SALT_LENGTH];
        let key = derive_key_from_password(password, &salt, &KdfParams::current()).unwrap();

        assert_eq!(
            key.len(),
            KEY_LENGTH,
            "Key should be exactly KEY_LENGTH bytes"
        );
    }

    // ==================== Salt & Nonce Generation Tests ====================

    #[test]
    fn test_generate_salt_length() {
        let salt = generate_salt();
        assert_eq!(salt.len(), SALT_LENGTH);
    }

    #[test]
    fn test_generate_salt_randomness() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2, "Generated salts should be unique");
    }

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), NONCE_LENGTH);
    }

    #[test]
    fn test_generate_nonce_randomness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2, "Generated nonces should be unique");
    }

    // ==================== Low-Level Encrypt/Decrypt Tests ====================

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_output() {
        let key = [0u8; KEY_LENGTH];
        let nonce1 = [0u8; NONCE_LENGTH];
        let nonce2 = [1u8; NONCE_LENGTH];
        let plaintext = b"Hello, World!";

        let ciphertext1 = encrypt(&key, &nonce1, plaintext).unwrap();
        let ciphertext2 = encrypt(&key, &nonce2, plaintext).unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Different nonces should produce different ciphertext"
        );
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [0u8; KEY_LENGTH];
        let key2 = [1u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key1, &nonce, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);

        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_wrong_nonce_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce1 = [0u8; NONCE_LENGTH];
        let nonce2 = [1u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key, &nonce1, plaintext).unwrap();
        let result = decrypt(&key, &nonce2, &ciphertext);

        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_large_data() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB

        let ciphertext = encrypt(&key, &nonce, &plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_includes_auth_tag() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Hello";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();

        // ChaCha20-Poly1305 adds a 16-byte auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let truncated = &ciphertext[..ciphertext.len() - 1];

        let result = decrypt(&key, &nonce, truncated);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    // ==================== File Format Tests ====================

    #[test]
    fn test_encrypted_roundtrip() {
        let password = b"test_password_123";
        let plaintext = b"Hello, World! This is a secret message.";
        let filename = "test_encrypted_roundtrip.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = b"correct_password";
        let wrong_password = b"wrong_password";
        let plaintext = b"Secret data";
        let filename = "test_wrong_password_fails.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let result = decrypt_file(wrong_password, &encrypted);

        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let data = b"NOTLOCK\x01xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = decrypt_file(b"password", data);
        assert!(matches!(result, Err(LockboxError::InvalidFileFormat)));
    }

    #[test]
    fn test_file_too_small() {
        let data = b"LOCKBOX";
        let result = decrypt_file(b"password", data);
        assert!(matches!(result, Err(LockboxError::InvalidFileFormat)));
    }

    #[test]
    fn test_invalid_version() {
        // Create valid header but with wrong version
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC_BYTES);
        data.push(99); // Invalid version
        data.extend_from_slice(&[0u8; 50]); // Padding

        let result = decrypt_file(b"password", &data);
        assert!(matches!(result, Err(LockboxError::InvalidFileFormat)));
    }

    #[test]
    fn test_empty_file_encryption() {
        let password = b"password";
        let plaintext = b"";
        let filename = "empty.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_unicode_filename() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "文件名_тест_🔐.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
    }

    #[test]
    fn test_long_filename() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "a".repeat(255);

        let encrypted = create_encrypted_file(password, &filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
    }

    #[test]
    fn test_file_with_spaces_in_name() {
        let password = b"password";
        let plaintext = b"content";
        let filename = "my secret file.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
    }

    #[test]
    fn test_binary_data_encryption() {
        let password = b"password";
        // Binary data with all byte values
        let plaintext: Vec<u8> = (0u8..=255).collect();
        let filename = "binary.bin";

        let encrypted = create_encrypted_file(password, filename, &plaintext).unwrap();
        let (_, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_encrypted_file_structure() {
        let password = b"password";
        let plaintext = b"test";
        let filename = "test.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Verify magic bytes
        assert_eq!(&encrypted[0..8], MAGIC_BYTES);

        // Verify version
        assert_eq!(encrypted[8], FORMAT_VERSION);

        // Verify KDF params (v2 format)
        let kdf = KdfParams::current();
        let memory =
            u32::from_be_bytes([encrypted[9], encrypted[10], encrypted[11], encrypted[12]]);
        assert_eq!(memory, kdf.memory_kib);
        let iterations =
            u32::from_be_bytes([encrypted[13], encrypted[14], encrypted[15], encrypted[16]]);
        assert_eq!(iterations, kdf.iterations);
        let parallelism =
            u32::from_be_bytes([encrypted[17], encrypted[18], encrypted[19], encrypted[20]]);
        assert_eq!(parallelism, kdf.parallelism);

        // Verify filename length (big-endian u16)
        let filename_len = u16::from_be_bytes([encrypted[21], encrypted[22]]) as usize;
        assert_eq!(filename_len, filename.len());

        // Verify filename
        let stored_filename = std::str::from_utf8(&encrypted[23..23 + filename_len]).unwrap();
        assert_eq!(stored_filename, filename);
    }

    #[test]
    fn test_different_encryptions_produce_different_output() {
        let password = b"password";
        let plaintext = b"same data";
        let filename = "file.txt";

        let encrypted1 = create_encrypted_file(password, filename, plaintext).unwrap();
        let encrypted2 = create_encrypted_file(password, filename, plaintext).unwrap();

        // Due to random salt and nonce, outputs should differ
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_corrupted_salt_fails() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "test.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Corrupt the salt area (v2: after magic + version + kdf(12) + filename_len(2) + filename)
        let salt_offset = 23 + filename.len();
        encrypted[salt_offset] ^= 0xFF;

        let result = decrypt_file(password, &encrypted);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_corrupted_nonce_fails() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "test.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Corrupt the nonce area (v2: after salt)
        let nonce_offset = 23 + filename.len() + SALT_LENGTH;
        encrypted[nonce_offset] ^= 0xFF;

        let result = decrypt_file(password, &encrypted);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_special_characters_in_password() {
        let password = "pässwörd🔐!@#$%^&*()".as_bytes();
        let plaintext = b"secret";
        let filename = "file.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (_, recovered) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_very_long_password() {
        let password = vec![b'a'; 10000];
        let plaintext = b"data";
        let filename = "file.txt";

        let encrypted = create_encrypted_file(&password, filename, plaintext).unwrap();
        let (_, recovered) = decrypt_file(&password, &encrypted).unwrap();

        assert_eq!(recovered, plaintext);
    }

    // ==================== Filename Boundary Tests ====================

    #[test]
    fn test_filename_at_u16_max_boundary() {
        let password = b"password";
        let plaintext = b"data";
        // Exactly 65535 bytes — the maximum the u16 length field can represent
        let filename = "a".repeat(u16::MAX as usize);

        let encrypted = create_encrypted_file(password, &filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_filename_exceeds_u16_max_fails() {
        let password = b"password";
        let plaintext = b"data";
        // 65536 bytes — one more than the u16 max
        let filename = "a".repeat(u16::MAX as usize + 1);

        let result = create_encrypted_file(password, &filename, plaintext);
        assert!(
            matches!(result, Err(LockboxError::EncryptionFailed(_))),
            "Filename exceeding u16::MAX bytes should fail"
        );
    }

    #[test]
    fn test_filename_length_field_lies_too_large() {
        // Craft a file where the filename length field claims more bytes than exist
        let password = b"password";
        let plaintext = b"data";
        let filename = "test.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Overwrite filename length with a huge value (v2: offset 21)
        let fake_len: u16 = 60000;
        encrypted[21] = fake_len.to_be_bytes()[0];
        encrypted[22] = fake_len.to_be_bytes()[1];

        let result = decrypt_file(password, &encrypted);
        assert!(
            result.is_err(),
            "Lying filename length field should cause a parse error"
        );
    }

    #[test]
    fn test_non_utf8_filename_in_encrypted_data() {
        // Manually construct encrypted data with invalid UTF-8 in the filename field (v2 format)
        let password = b"password";
        let kdf = KdfParams::current();
        let salt = [0u8; SALT_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let key = derive_key_from_password(password, &salt, &kdf).unwrap();
        let ciphertext = encrypt(&key, &nonce, b"data").unwrap();

        let invalid_utf8_filename: &[u8] = &[0xFF, 0xFE, 0x80, 0x81];

        let mut data = Vec::new();
        data.extend_from_slice(MAGIC_BYTES);
        data.push(FORMAT_VERSION);
        data.extend_from_slice(&kdf.memory_kib.to_be_bytes());
        data.extend_from_slice(&kdf.iterations.to_be_bytes());
        data.extend_from_slice(&kdf.parallelism.to_be_bytes());
        data.extend_from_slice(&(invalid_utf8_filename.len() as u16).to_be_bytes());
        data.extend_from_slice(invalid_utf8_filename);
        data.extend_from_slice(&salt);
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);

        let result = decrypt_file(password, &data);
        assert!(
            matches!(result, Err(LockboxError::InvalidFileFormat)),
            "Non-UTF-8 filename should return InvalidFileFormat"
        );
    }

    #[test]
    fn test_filename_with_path_separators() {
        // A filename containing slashes should round-trip at the crypto layer
        // (path traversal sanitization is handled in file_ops, not here)
        let password = b"password";
        let plaintext = b"data";
        let filename = "../../etc/passwd";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_empty_filename() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, "");
    }

    // ==================== Double Encryption Test ====================

    #[test]
    fn test_double_encryption_roundtrip() {
        let password1 = b"first_password";
        let password2 = b"second_password";
        let plaintext = b"original content";
        let filename = "secret.txt";

        // First encryption
        let encrypted_once = create_encrypted_file(password1, filename, plaintext).unwrap();

        // Second encryption (encrypting the already-encrypted blob)
        let encrypted_twice =
            create_encrypted_file(password2, "secret.lb", &encrypted_once).unwrap();

        // Decrypt outer layer
        let (outer_filename, inner_blob) = decrypt_file(password2, &encrypted_twice).unwrap();
        assert_eq!(outer_filename, "secret.lb");

        // Decrypt inner layer
        let (inner_filename, recovered_plaintext) = decrypt_file(password1, &inner_blob).unwrap();
        assert_eq!(inner_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    // ==================== Truncation & Boundary Tests ====================

    #[test]
    fn test_file_exactly_minimum_size_but_invalid() {
        // Construct data that is exactly the v2 minimum size (67 bytes for empty filename)
        // but has valid magic/version so it reaches the decrypt stage and fails auth
        let min_size: usize = 8 + 1 + 12 + 2 + 16 + 12 + 16; // 67
        let mut data = vec![0u8; min_size];
        data[..8].copy_from_slice(MAGIC_BYTES);
        data[8] = FORMAT_VERSION;
        // KDF params and filename_len = 0 (already zeroed)

        let result = decrypt_file(b"password", &data);
        // Should fail at decryption (wrong key / zero KDF params) not at parsing
        // Note: zero KDF params (0 memory, 0 iterations, 0 parallelism) will cause
        // an Argon2 param error, which surfaces as EncryptionFailed
        assert!(
            result.is_err(),
            "Minimum-size file with valid header should fail"
        );
    }

    #[test]
    fn test_file_one_byte_below_minimum_size() {
        let min_size: usize = 8 + 1 + 12 + 2 + 16 + 12 + 16; // 67
        let mut data = vec![0u8; min_size - 1];
        data[..8].copy_from_slice(MAGIC_BYTES);
        data[8] = FORMAT_VERSION;

        let result = decrypt_file(b"password", &data);
        assert!(
            matches!(result, Err(LockboxError::InvalidFileFormat)),
            "File below minimum size should be rejected as invalid format"
        );
    }

    // ==================== Version 2 Format Tests ====================

    #[test]
    fn test_v2_format_roundtrip() {
        let password = b"test_v2_roundtrip";
        let plaintext = b"Version 2 format test data with some content.";
        let filename = "v2_test.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Verify it is v2
        assert_eq!(encrypted[8], 2);

        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();
        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_v1_backward_compatibility() {
        // Manually construct a v1-format file and verify decrypt_file can parse it
        let password = b"v1_compat_password";
        let filename = "legacy.txt";
        let plaintext = b"Legacy v1 data";

        // Use the v1 hardcoded KDF params to derive key
        let v1_kdf = KdfParams {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
        };
        let salt = generate_salt();
        let nonce = generate_nonce();
        let key = derive_key_from_password(password, &salt, &v1_kdf).unwrap();
        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();

        // Build a v1-format file manually
        let filename_bytes = filename.as_bytes();
        let filename_len = filename_bytes.len() as u16;
        let mut v1_data = Vec::new();
        v1_data.extend_from_slice(MAGIC_BYTES);
        v1_data.push(1); // version 1
        v1_data.extend_from_slice(&filename_len.to_be_bytes());
        v1_data.extend_from_slice(filename_bytes);
        v1_data.extend_from_slice(&salt);
        v1_data.extend_from_slice(&nonce);
        v1_data.extend_from_slice(&ciphertext);

        // decrypt_file should handle v1 format
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &v1_data).unwrap();
        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_custom_kdf_params_roundtrip() {
        // Create an encrypted file with non-default KdfParams and verify decryption works
        let password = b"custom_kdf_password";
        let plaintext = b"Custom KDF params test data";
        let filename = "custom_kdf.txt";

        let custom_kdf = KdfParams {
            memory_kib: 32768, // 32 MiB instead of 64 MiB
            iterations: 2,     // 2 instead of 3
            parallelism: 2,    // 2 instead of 4
        };

        let encrypted =
            create_encrypted_file_with_params(password, filename, plaintext, &custom_kdf).unwrap();

        // Verify header stores the custom params
        let memory =
            u32::from_be_bytes([encrypted[9], encrypted[10], encrypted[11], encrypted[12]]);
        assert_eq!(memory, 32768);
        let iterations =
            u32::from_be_bytes([encrypted[13], encrypted[14], encrypted[15], encrypted[16]]);
        assert_eq!(iterations, 2);
        let parallelism =
            u32::from_be_bytes([encrypted[17], encrypted[18], encrypted[19], encrypted[20]]);
        assert_eq!(parallelism, 2);

        // Decrypt should read the params from the header and succeed
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();
        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_v2_encrypted_file_structure() {
        // Verify the exact header layout of v2 files
        let password = b"password";
        let plaintext = b"structure test";
        let filename = "struct.dat";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let kdf = KdfParams::current();

        // Magic bytes at offset 0..8
        assert_eq!(&encrypted[0..8], MAGIC_BYTES);

        // Version at offset 8
        assert_eq!(encrypted[8], 2u8);

        // KDF memory at offset 9..13
        assert_eq!(
            u32::from_be_bytes([encrypted[9], encrypted[10], encrypted[11], encrypted[12]]),
            kdf.memory_kib
        );

        // KDF iterations at offset 13..17
        assert_eq!(
            u32::from_be_bytes([encrypted[13], encrypted[14], encrypted[15], encrypted[16]]),
            kdf.iterations
        );

        // KDF parallelism at offset 17..21
        assert_eq!(
            u32::from_be_bytes([encrypted[17], encrypted[18], encrypted[19], encrypted[20]]),
            kdf.parallelism
        );

        // Filename length at offset 21..23
        let filename_len = u16::from_be_bytes([encrypted[21], encrypted[22]]) as usize;
        assert_eq!(filename_len, filename.len());

        // Filename at offset 23..23+N
        let stored_filename = std::str::from_utf8(&encrypted[23..23 + filename_len]).unwrap();
        assert_eq!(stored_filename, filename);

        // Salt at offset 23+N..39+N (16 bytes)
        let salt_start = 23 + filename_len;
        assert_eq!(
            encrypted[salt_start..salt_start + SALT_LENGTH].len(),
            SALT_LENGTH
        );

        // Nonce at offset 39+N..51+N (12 bytes)
        let nonce_start = salt_start + SALT_LENGTH;
        assert_eq!(
            encrypted[nonce_start..nonce_start + NONCE_LENGTH].len(),
            NONCE_LENGTH
        );

        // Ciphertext + auth tag at offset 51+N..end
        let ciphertext_start = nonce_start + NONCE_LENGTH;
        let ciphertext_len = encrypted.len() - ciphertext_start;
        // plaintext(14) + auth_tag(16) = 30
        assert_eq!(ciphertext_len, plaintext.len() + 16);
    }
}
