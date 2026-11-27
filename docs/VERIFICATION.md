# Verification evidence

The integration run used Rust 1.88.0 on Linux x86_64 with Localwright pinned to the revision in `Cargo.lock`. Formatting, locked all-target checking, default and headless tests, strict Clippy, and CLI help passed.

Signature tests and the scan fixture passed. Python hashlib independently confirmed the SHA-256 in the CLI JSON output.

The ordinary `Check` workflow is a fast Linux x64 validation gate with a stable `Rust (ubuntu-24.04)` job context. Markdown-only changes run registry validation and patch checks without compiling Cargo targets. Default/headless and virtual-display launch checks are in the manually dispatched or `integration`-labeled Integration workflow. Five native target build/test checks are in the manual or `native-validation`-labeled workflow. Optimized builds and portable preview uploads are manual only. Device tests and installer lifecycle verification remain open.

The scheduled/manual Security and dependency review workflow runs a locked RustSec audit and generates CycloneDX plus declared-license/notice inventory artifacts. The inventory identifies review inputs; it does not approve third-party licenses or native assets. These workflow changes have not yet received hosted verification in this branch.

On 2026-11-27, the locked headless suite passed 16 tests and strict Clippy passed on Linux x86_64 with Rust 1.88.0. Directory ZIP creation/extraction passed a Unicode nested-file round trip and a traversal archive was refused without creating output. SHA-256 manifest fixtures detected changed and missing files and rejected a traversal path. The capability registry JSON and whitespace checks passed. This does not verify GUI dialogs or native installer targets.

For the age encryption increment on Linux x86_64 with Rust 1.88.0, `cargo check --locked --no-default-features`, `cargo test --locked --no-default-features` (22 tests), formatting, and strict all-target Clippy passed. Fixtures exercised binary and empty-file round-trips, public/private key separation, owner-only Unix identity permissions, wrong-key rejection, modified ciphertext rejection without plaintext publication, output collision preservation, cancellation, and symlink refusal. Windows identity and decrypted output paths are restricted to the user profile. Hosted run `45998435551` passed the default-feature builds, tests, headless checks and portable previews on all five targets. Dependency audit and package/device lifecycle checks remain.
