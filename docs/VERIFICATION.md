# Verification evidence

The integration run used Rust 1.88.0 on Linux x86_64 with Localwright pinned to the revision in `Cargo.lock`. Formatting, locked all-target checking, default and headless tests, strict Clippy, and CLI help passed.

Signature tests and the scan fixture passed. Python hashlib independently confirmed the SHA-256 in the CLI JSON output.

The GitHub workflow defines five platform checks. Device tests and installer verification remain open.

On 2026-11-27, the locked headless suite passed 16 tests and strict Clippy passed on Linux x86_64 with Rust 1.88.0. Directory ZIP creation/extraction passed a Unicode nested-file round trip and a traversal archive was refused without creating output. SHA-256 manifest fixtures detected changed and missing files and rejected a traversal path. The capability registry JSON and whitespace checks passed. This does not verify GUI dialogs or native installer targets.

For the age encryption increment on Linux x86_64 with Rust 1.88.0, `cargo check --locked --no-default-features`, `cargo test --locked --no-default-features` (22 tests), formatting, and strict all-target Clippy passed. Fixtures exercised binary and empty-file round-trips, public/private key separation, owner-only Unix identity permissions, wrong-key rejection, modified ciphertext rejection without plaintext publication, output collision preservation, cancellation, and symlink refusal. GUI/default-feature compilation, the five-target hosted matrix, dependency audit, and package/device checks remain pending.
