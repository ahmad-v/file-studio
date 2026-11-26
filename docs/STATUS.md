# Status | 0.1.0-alpha.1

M0 complete as source planning; partial M1 implementation, not verified. All five repos created locally as source trees only. No remote resources created.

| Operation | Scope | Status |
|---|---|---|
| inspect | Signature subset, SHA-256/BLAKE3; JSON | implemented-unverified |
| scan | Bounded directory inventory; JSON/CSV | implemented-unverified |

## Known gaps

Signature identification is a limited prefix test, not exhaustive or format validation. Scanning aborts on unreadable entries; no volume catalogue, duplicate analysis, metadata sanitation, archives, encryption or backup. File metadata comparison cannot detect every concurrent modification or path race. No timestamps in report yet.

Cargo and rustc absent; registry and distribution DNS failed. No lockfile, compilation, rustfmt, clippy, Rust tests, GUI/device tests, package builds or security audit performed. All five platform builds blocked pending CI. See MASTER_SPECIFICATION.md for authoritative acceptance gates.
