# Ironlock 🔐

[![Crates.io](https://img.shields.io/crates/v/ironlock.svg)](https://crates.io/crates/ironlock)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/christurgeon/ironlock/actions/workflows/ci.yml/badge.svg)](https://github.com/christurgeon/ironlock/actions/workflows/ci.yml)

A secure file encryption CLI tool built in Rust. Ironlock uses industry-standard cryptographic primitives to protect your files with a password.

## Installation

### From crates.io (recommended)

```bash
cargo install ironlock
```

### From Source

```bash
git clone https://github.com/christurgeon/ironlock.git
cd ironlock
cargo build --release
cp ./target/release/ironlock ~/.local/bin/
```

## Quick Start

```bash
# Encrypt a file (password prompt will appear)
ironlock encrypt secret.txt
# Creates: secret.il

# Decrypt a file
ironlock decrypt secret.il
# Restores: secret.txt
```

## Usage

### Encrypt Files

```bash
# Encrypt a single file
ironlock encrypt secret.txt

# Encrypt multiple files
ironlock encrypt document.pdf image.png notes.md

# Force overwrite of existing .il files
ironlock encrypt secret.txt --force

# Securely delete originals after encryption (3-pass random overwrite)
ironlock encrypt secret.txt --shred

# Combine flags
ironlock encrypt secret.txt -f -s
```

You'll be prompted to enter and confirm your password (hidden input):

```
🔐 Ironlock Encryption

Enter password:
Confirm password:

Encrypting secret.txt ... ✓ → secret.il
```

> **Note:** The original file extension is encrypted inside the `.il` file and will be restored on decryption. This hides the file type from observers.

### Decrypt Files

```bash
# Decrypt a single file
ironlock decrypt secret.il

# Decrypt to a specific directory
ironlock decrypt secret.il --output ./decrypted/

# Decrypt multiple files
ironlock decrypt file1.il file2.il file3.il -o ./output/

# Force overwrite of existing files
ironlock decrypt secret.il --force
```

### Directory Encryption

Ironlock can recursively encrypt or decrypt entire directories, preserving the directory structure:

```bash
# Encrypt all files in a directory
ironlock encrypt ./my-folder/

# Decrypt all .il files in a directory to an output location
ironlock decrypt ./my-folder/ -o ./decrypted/

# Encrypt a directory and securely delete the originals
ironlock encrypt ./sensitive-docs/ --shred
```

### Piping (Stdin/Stdout)

Ironlock supports reading from stdin and writing to stdout for composability with other tools. When no files are provided and stdin is piped, Ironlock operates in streaming mode:

```bash
# Encrypt from stdin to a file
cat secret.txt | ironlock encrypt > secret.il

# Decrypt from stdin to a file
cat secret.il | ironlock decrypt > secret.txt

# Chain with other tools
tar cf - ./docs/ | ironlock encrypt > docs.tar.il
cat docs.tar.il | ironlock decrypt | tar xf -
```

Password prompts are written to stderr, so they won't interfere with piped data.

### Command Aliases

For convenience, shorthand aliases are available:

| Command | Aliases |
|---------|---------|
| `encrypt` | `enc`, `e` |
| `decrypt` | `dec`, `d` |

```bash
ironlock e secret.txt        # same as: ironlock encrypt secret.txt
ironlock d secret.il -o out/ # same as: ironlock decrypt secret.il -o out/
```

### Flags Reference

#### Encrypt

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Overwrite existing `.il` files without prompting |
| `--shred` | `-s` | Securely delete originals after encryption (also `--delete`) |
| `--progress` | `-p` | Show a progress bar when processing multiple files |

#### Decrypt

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Overwrite existing output files without prompting |
| `--output <DIR>` | `-o` | Output directory for decrypted files |
| `--progress` | `-p` | Show a progress bar when processing multiple files |

## Security

Ironlock uses the following cryptographic primitives:

- **Argon2id** for password-based key derivation (64 MiB memory, 3 iterations, 4 parallelism)
- **ChaCha20-Poly1305** for authenticated encryption (256-bit keys, 96-bit nonces)
- **Authenticated header** — the file header (magic bytes, version, KDF params, filename, salt, nonce) is passed as AEAD associated data, preventing undetected tampering
- **Secure memory handling** via `zeroize` (key material zeroed on drop) and `mlock` (prevents swap to disk on Unix)
- **Secure deletion** via `--shred` overwrites files with cryptographically random data (3 passes) before unlinking

KDF parameters are stored in the encrypted file header, allowing future upgrades without breaking existing files.

> **Note:** Ironlock currently loads entire files into memory. A warning is displayed for files over 1 GiB. For very large files, consider available RAM or use stdin piping.

## Development

```bash
# Run tests
cargo test

# Run lints
cargo clippy

# Format code
cargo fmt

# Build release
cargo build --release
```

## Uninstalling

```bash
cargo uninstall ironlock
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT License - see [LICENSE](LICENSE) for details.
