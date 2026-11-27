# Status | 0.1.0-alpha.1

Alpha source is on GitHub. The initial Rust integration checks ran on Linux x86_64.

| Operation | Scope | Status |
|---|---|---|
| catalog-compare | Compare paths and sizes in saved inventories | Linux fixture-tested |
| file-times | Read creation, modification and access timestamps | Linux fixture-tested |
| duplicates | Read-only duplicate candidate groups | Linux fixture-tested |
| directory-usage | Logical directory size report | Linux fixture-tested |
| png-metadata / png-strip-metadata | Inspect PNG chunks and remove text or EXIF metadata from a copy | Linux fixture and independent pixel-verified CLI |
| hex-preview | Bounded offset window with hex and printable ASCII | Linux fixture and CLI-tested |
| inspect | Signature subset, SHA-256/SHA-512/BLAKE3; JSON | Linux fixture-tested |
| verify | SHA-256, SHA-512 or BLAKE3 against a supplied checksum; JSON on match | Linux fixture-tested |
| zip-extract-entry | Extract one numbered regular entry to a chosen path | Linux fixture and CLI-tested |
| zip-create | One regular file as a Deflate ZIP with a portable entry name | Linux fixture and CLI-tested |
| zip-create-directory | Recursively create a ZIP from regular directory files | Linux fixture-tested |
| zip-extract-all | Extract a bounded ZIP to a new directory with traversal/link rejection | Linux round-trip and traversal fixture-tested |
| manifest-create / manifest-verify | Versioned relative-path SHA-256 manifest and match/change/missing report | Linux fixture-tested |
| age-keygen | Generate a standard X25519 identity and save it with owner-only permissions on Unix | Linux fixture-tested |
| age-encrypt / age-decrypt | Streaming age X25519 encryption and authenticated decryption; reject weak Unix identity-file permissions and never overwrite outputs | Linux fixture-tested |
| zip-test | Stored and Deflate ZIP checksum tests without extraction | Linux fixture-tested |
| zip-list | ZIP directory listing; JSON | Linux fixture-tested |
| catalog-search | Search a saved version 1 inventory by path text | Linux unit fixture and CLI-tested |
| scan | Bounded directory inventory; JSON/CSV | Linux fixture-tested |

## Known gaps

Signature identification is a limited prefix test, not exhaustive or format validation. Scanning aborts on unreadable entries; there is no persistent volume catalogue, metadata sanitation outside the supported PNG chunks, digital signature verification, or backup. Age identity generation currently creates an unencrypted private key file; keep it in a user-controlled location and maintain a secure backup. Unix permissions are checked. Windows restricts identity and decrypted output paths to the user profile and relies on inherited directory ACLs, which are not independently audited. Age encryption does not authenticate the sender. File encryption and decryption stream files up to 4 GiB and do not overwrite outputs. Directory ZIP routes skip empty directories and filesystem metadata, and cap input/output at 128 MiB total, 32 MiB per file and 4,096 entries. SHA-256 manifests are integrity records, not authenticated signatures. File metadata comparison cannot detect every concurrent modification or path race.

Hosted matrix, device, and packaging verification remain open. See [verification evidence](VERIFICATION.md) and [dependency review](DEPENDENCIES.md).
