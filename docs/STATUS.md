# Status | 0.1.0-alpha.1

Alpha source is on GitHub. The initial Rust integration checks ran on Linux x86_64.

| Operation | Scope | Status |
|---|---|---|
| directory-usage | Logical directory size report | implemented-unverified |
| inspect | Signature subset, SHA-256/SHA-512/BLAKE3; JSON | Linux fixture-tested |
| verify | SHA-256, SHA-512 or BLAKE3 against a supplied checksum; JSON on match | Linux fixture-tested |
| zip-list | ZIP directory listing; JSON | Linux fixture-tested |
| scan | Bounded directory inventory; JSON/CSV | Linux fixture-tested |

## Known gaps

Signature identification is a limited prefix test, not exhaustive or format validation. Scanning aborts on unreadable entries; no volume catalogue, duplicate analysis, metadata sanitation, archive extraction or creation, encryption or backup. File metadata comparison cannot detect every concurrent modification or path race. No timestamps in report yet.

Hosted matrix, device, and packaging verification remain open. See [verification evidence](VERIFICATION.md) and [dependency review](DEPENDENCIES.md).
