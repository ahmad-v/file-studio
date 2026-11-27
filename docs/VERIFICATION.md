# Verification evidence

The integration run used Rust 1.88.0 on Linux x86_64 with Localwright pinned to the revision in `Cargo.lock`. Formatting, locked all-target checking, default and headless tests, strict Clippy, and CLI help passed.

Signature tests and the scan fixture passed. Python hashlib independently confirmed the SHA-256 in the CLI JSON output.

The GitHub workflow defines five platform checks. Device tests and installer verification remain open.

On 2026-11-27, the locked headless suite passed 16 tests and strict Clippy passed on Linux x86_64 with Rust 1.88.0. Directory ZIP creation/extraction passed a Unicode nested-file round trip and a traversal archive was refused without creating output. SHA-256 manifest fixtures detected changed and missing files and rejected a traversal path. The capability registry JSON and whitespace checks passed. This does not verify GUI dialogs or native installer targets.
