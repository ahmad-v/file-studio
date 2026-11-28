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
| gzip-create | Compress one regular file to a new GZIP stream with bounded streaming and cancellation | Implemented; tests added, hosted verification pending |
| gzip-extract | Validate and decompress concatenated GZIP members to a new file, capped at 1 GiB expanded | Implemented; tests added, hosted verification pending |
| gzip-test | Validate GZIP CRC and size while streaming to a sink | Implemented; tests added, hosted verification pending |
| zip-list | ZIP directory listing; JSON | Linux fixture-tested |
| catalog-search | Search a saved version 1 inventory by path text | Linux unit fixture and CLI-tested |
| catalog-history | List the latest 100 saved SQLite scan snapshots without opening the source volume | Rust 1.89 Linux default-feature integration tested; hosted five-target verification pending |
| catalog-compare-snapshots | Compare chosen retained scans; report source identity match and path/size deltas, offline | Focused Linux end-to-end fixture passed; hosted GUI/platform verification pending |
| catalog-refresh | Append schema-v3 snapshots; compare added/removed/changed paths by size and available modification time only for matching stable source identity; preserve history and migrate v1/v2 | Local migration and same-size timestamp-change fixtures pass; hosted verification pending |
| scan | Bounded directory inventory; JSON/CSV or new SQLite snapshot | Linux JSON/CSV/SQLite fixture-tested; five-target hosted verification pending |

## Native catalogue workspace

The GUI starts on a Catalogue page with native file/folder pickers, read-only path-fragment search over a saved SQLite snapshot, a sortable paginated Localwright table for results (50 rows per page) and history (20 rows per page), and refresh that appends a complete scan. A dedicated create flow selects a source folder and a new SQLite path, scans in the background, supports cooperative cancellation, rejects overwrite through the existing no-clobber writer, and opens the newly created catalogue history. Each result can be inspected when the user chooses its source folder; the read-only view revalidates the relative path and displays the existing inspector report (hashes, available timestamps, bounded hex sample, and supported PNG properties). Refresh progress is indeterminate during directory traversal and determinate while SQLite rows are added; polling runs only while a job is active, and cancellation remains available. History shows deltas only for matching source identities. Selecting two history rows fills the comparison scan IDs, and users can compare any two retained snapshots entirely offline; the report shows added, removed, size-changed and same-size paths and explicitly identifies whether both snapshots have the same stable source identity. The Operations page retains all registered File Studio operations. Unit tests cover bounded result/history parsing, table sorting, selection, pagination behavior, input validation, settings compatibility, native non-Unicode paths and the progress display model. Native visual/usability, screen-reader and accessibility review remain pending.

## Known gaps

The Catalogue workspace additionally scans a selected source folder for matching BLAKE3 content-hash groups, displays up to 20 groups at a time with up to eight paths per group, and never deletes or moves files. This is a live read-only scan rather than disconnected catalogue analysis; candidate hashing is limited to 1 GiB. The new duplicate-report parser and native workflow tests are local-only until the corresponding PR checks pass.

Signature identification is a limited prefix test, not exhaustive or format validation. Inaccessible paths and safety limits mark scans partial; partial JSON reports cannot be loaded as complete inventories and partial scans do not create catalogue snapshots or removal counts. The local SQLite catalogue records append-only history and supports disconnected path search. Unix scan-root identity uses filesystem device plus inode; Windows now uses volume serial plus root-directory file index through the `file-id` crate. Targets without stable identity use full-rescan baselines. Refresh still traverses the complete tree and does not use filesystem change journals. Same-size content changes are not detected. The native result inspector reads only after the user chooses a source folder and revalidates every path component, but filesystem replacement races cannot be ruled out on all platforms. Catalogue database paths are canonicalized after final-file symlink checks to support macOS symlinked temporary-directory parents. Metadata sanitation outside supported PNG chunks, digital signature verification, and backup remain unavailable. Age identity generation currently creates an unencrypted private key file; keep it in a user-controlled location and maintain a secure backup. Unix permissions are checked. Windows restricts identity and decrypted output paths to the user profile and relies on inherited directory ACLs, which are not independently audited. Age encryption does not authenticate the sender. File encryption and decryption stream files up to 4 GiB and do not overwrite outputs. Directory ZIP routes skip empty directories and filesystem metadata, and cap input/output at 128 MiB total, 32 MiB per file and 4,096 entries. GZIP routes handle single-file streams (including concatenated read members), cap compressed and expanded content at 1 GiB, and omit source filesystem metadata. GZIP CRC is not authenticity. SHA-256 manifests are integrity records, not authenticated signatures. File metadata comparison cannot detect every concurrent modification or path race.

The five-target hosted build/test/preview matrix passed for the age encryption increment. Device and full packaging lifecycle verification remain open. See [verification evidence](VERIFICATION.md) and [dependency review](DEPENDENCIES.md).

## CI workflow architecture

Ordinary pull requests and pushes to `main` use the Linux x64 `Check` job for formatting, locked all-target checks/tests, strict Clippy, metadata validation and registry validation. Markdown-only changes retain the same check context while skipping Cargo work. `Integration` covers default GUI and headless tests plus virtual-display launch on manual dispatch or the `integration` PR label. `Native platform validation` covers all five target build/test jobs on manual dispatch or the `native-validation` PR label. `Distribution preview` manually produces optimized unsigned portable evaluation bundles only; installable package workflows remain blocked by unresolved identities, build-tool provisioning and device acceptance. Weekly/manual Security and dependency review runs RustSec and generates CycloneDX and declared-license/notice inventory evidence. Its generated license report is not a legal approval. This CI refactor is awaiting its initial hosted run.
