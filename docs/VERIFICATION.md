# Verification evidence

The integration run used Rust 1.88.0 on Linux x86_64 with Localwright pinned to the revision in `Cargo.lock`. Formatting, locked all-target checking, default and headless tests, strict Clippy, and CLI help passed.

Signature tests and the scan fixture passed. Python hashlib independently confirmed the SHA-256 in the CLI JSON output.

The GitHub workflow defines five platform checks. Device tests and installer verification remain open.
