# Status | 0.1.0-alpha.1

Alpha source is on GitHub. The initial Rust integration checks ran on Linux x86_64.

| Operation | Scope | Status |
|---|---|---|
| duplicates | Read-only duplicate candidate groups | Linux fixture-tested |
| directory-usage | Logical directory size report | Linux fixture-tested |
| hex-preview | Bounded offset window with hex and printable ASCII | Linux fixture and CLI-tested |
| inspect | Signature subset, SHA-256/SHA-512/BLAKE3; JSON | Linux fixture-tested |
| verify | SHA-256, SHA-512 or BLAKE3 against a supplied checksum; JSON on match | Linux fixture-tested |
| zip-extract-entry | Extract one numbered regular entry to a chosen path | Linux fixture and CLI-tested |
| zip-create | One regular file as a Deflate ZIP with a portable entry name | Linux fixture and CLI-tested |
| zip-test | Stored and Deflate ZIP checksum tests without extraction | Linux fixture-tested |
| zip-list | ZIP directory listing; JSON | Linux fixture-tested |
| scan | Bounded directory inventory; JSON/CSV | Linux fixture-tested |

## Known gaps

Signature identification is a limited prefix test, not exhaustive or format validation. Scanning aborts on unreadable entries; no persistent volume catalogue, metadata sanitation, whole-archive extraction or multi-file creation, encryption or backup. File metadata comparison cannot detect every concurrent modification or path race. No timestamps in report yet.

Hosted matrix, device, and packaging verification remain open. See [verification evidence](VERIFICATION.md) and [dependency review](DEPENDENCIES.md).
