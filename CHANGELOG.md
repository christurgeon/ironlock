# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-03-20

### Added

- File encryption and decryption using Argon2id + ChaCha20-Poly1305
- Authenticated header via AEAD associated data
- Multi-file and directory support with recursive traversal
- Stdin/stdout piping for composability with other tools
- `--shred` flag for secure deletion (3-pass random overwrite)
- `--force` flag to overwrite existing files
- `--output` flag for custom decryption output directory
- `--progress` / `-p` flag to show a progress bar
- Large file warning for files over 1 GiB
- Command aliases (`e`/`enc` for encrypt, `d`/`dec` for decrypt)
- Secure memory handling with `zeroize` and `mlock`
- KDF parameters stored in file header for forward compatibility
- Colored terminal output with progress indicators
- GitHub Actions CI (test, clippy, fmt)

[0.1.0]: https://github.com/christurgeon/ironlock/releases/tag/v0.1.0
