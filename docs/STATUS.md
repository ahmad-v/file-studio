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
| inspect | Combined signature subset, size, SHA-256/SHA-512/BLAKE3, available timestamps, bounded hex sample, and verified PNG chunk counts | Linux fixture-tested; hosted matrix pending on current branch |
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
| catalog-history | List the latest 100 saved SQLite scan snapshots without opening the source volume | Rust 1.89 Linux default-feature integration tested; hosted five-target verification pending |
| catalog-refresh | Append a versioned SQLite scan snapshot while preserving previous history | Rust 1.89 Linux default-feature integration tested; hosted five-target verification pending |
| scan | Bounded directory inventory; JSON/CSV or new SQLite snapshot | Linux JSON/CSV/SQLite fixture-tested; five-target hosted verification pending |

## Native catalogue workspace

The GUI starts on a Catalogue page with native file/folder pickers, read-only path-fragment search over a saved SQLite snapshot, a paginated result table (100 rows per page), recent scan-history rows, and a refresh action that appends a new complete scan through the existing `catalog-refresh` route. The Operations page retains all registered File Studio operations. Unit tests were added for bounded result/history parsing, pagination behavior, input validation, settings compatibility and native non-Unicode paths. The initial UI/view-model implementation was type-checked, but tests were not executed because `cargo test --locked` stopped on workspace disk exhaustion (ENOSPC); the final path-preservation adapter edits received formatting checks only. Native visual/usability, screen-reader and accessibility review remain pending.

## Known gaps

Signature identification is a limited prefix test, not exhaustive or format validation. Scanning aborts on unreadable entries. The new local SQLite catalogue records versioned scan history and supports disconnected path search; stable volume identity, incremental filesystem change journals, metadata sanitation outside supported PNG chunks, digital signature verification, and backup remain unavailable. Age identity generation currently creates an unencrypted private key file; keep it in a user-controlled location and maintain a secure backup. Unix permissions are checked. Windows restricts identity and decrypted output paths to the user profile and relies on inherited directory ACLs, which are not independently audited. Age encryption does not authenticate the sender. File encryption and decryption stream files up to 4 GiB and do not overwrite outputs. Directory ZIP routes skip empty directories and filesystem metadata, and cap input/output at 128 MiB total, 32 MiB per file and 4,096 entries. SHA-256 manifests are integrity records, not authenticated signatures. File metadata comparison cannot detect every concurrent modification or path race.

The five-target hosted build/test/preview matrix passed for the age encryption increment. Device and full packaging lifecycle verification remain open. See [verification evidence](VERIFICATION.md) and [dependency review](DEPENDENCIES.md).

## CI workflow architecture

Ordinary pull requests and pushes to `main` use the Linux x64 `Check` job for formatting, locked all-target checks/tests, strict Clippy, metadata validation and registry validation. Markdown-only changes retain the same check context while skipping Cargo work. `Integration` covers default GUI and headless tests plus virtual-display launch on manual dispatch or the `integration` PR label. `Native platform validation` covers all five target build/test jobs on manual dispatch or the `native-validation` PR label. `Distribution preview` manually produces optimized unsigned portable evaluation bundles only; installable package workflows remain blocked by unresolved identities, build-tool provisioning and device acceptance. Weekly/manual Security and dependency review runs RustSec and generates CycloneDX and declared-license/notice inventory evidence. Its generated license report is not a legal approval. This CI refactor is awaiting its initial hosted run.
