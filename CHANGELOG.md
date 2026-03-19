# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-03-18

### Added

- File encryption and decryption using Argon2id + ChaCha20-Poly1305
- Multi-file and directory support with recursive traversal
- Stdin/stdout piping for composability with other tools
- `--shred` flag for secure deletion (3-pass random overwrite)
- `--force` flag to overwrite existing files
- `--output` flag for custom decryption output directory
- Command aliases (`e`/`enc` for encrypt, `d`/`dec` for decrypt)
- Secure memory handling with `zeroize` and `mlock`
- KDF parameters stored in file header for forward compatibility
- Colored terminal output with progress indicators

[0.1.0]: https://github.com/christurgeon/lockbox/releases/tag/v0.1.0
