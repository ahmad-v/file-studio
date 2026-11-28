# Format and operation compatibility

No capability is marked device-verified or released. Previous hosted jobs passed Linux and Windows targets; the current SQLite catalogue head awaits its native matrix. The machine-readable registry is a development inventory, not an advertised capability list.

| Operation | Route | Evidence status |
|---|---|---|
| catalog-compare | Compare JSON inventories or latest SQLite catalogue snapshots by path and size | Linux fixture-tested |
| catalog-history | Read the latest 100 SQLite scan snapshots without accessing original paths | Linux integration fixture-tested |
| catalog-refresh | Append schema-v3 full scans; classify additions, removals and changes using size plus available modification timestamps when stable source identity matches; migrate v1/v2 catalogues | Local migration and same-size timestamp-change fixtures pass; hosted verification pending |
| file-times | Read creation, modification and access timestamps | Linux fixture-tested |
| png-metadata / png-strip-metadata | PNG chunk inspection and removal of text and EXIF from a copy | Linux fixture-tested |
| hex-preview | Bounded offset window with hex and printable ASCII | Linux fixture and CLI-tested |
| inspect | Signature subset and integrity hashes for regular files; timestamps and bounded hex sample; PNG chunk counts for valid PNGs up to 32 MiB | Linux fixture-tested; other format properties unavailable |
| catalog-search | Search JSON inventory or versioned SQLite catalogue by path text | Linux unit fixture and CLI-tested |
| scan | Bounded directory inventory; JSON, CSV or a new SQLite snapshot | Linux integration fixture-tested |
| zip-extract-entry | Extract one numbered regular entry to a chosen path | Linux fixture and CLI-tested |
| zip-create | One regular file as a Deflate ZIP with a portable entry name | Linux fixture and CLI-tested |
| zip-create-directory | Regular files in a directory tree to Deflate ZIP; empty directories and filesystem metadata omitted | Linux round-trip fixture-tested |
| zip-extract-all | Bounded regular files/directories to a new folder; links, traversal and collisions rejected | Linux round-trip and malicious-path fixture-tested |
| gzip-create | One regular file compressed to a new `.gz` stream; source and output bounded to 1 GiB | Check, Integration, five-target Native, Distribution preview and dependency review passed at `93ddde8` |
| gzip-extract | Concatenated GZIP members to a new selected file; CRC checked; expanded output capped at 1 GiB | Check, Integration, five-target Native, Distribution preview and dependency review passed at `93ddde8` |
| gzip-test | Validate GZIP stream to a sink without publishing extracted bytes | Check, Integration, five-target Native, Distribution preview and dependency review passed at `93ddde8` |
| tar-list | Bounded POSIX/GNU TAR path and size listing; payloads are not read | Implemented; tests added; hosted verification pending |
| tar-test | Validate TAR headers and fully read regular members; TAR has no payload checksum | Implemented; tests added; hosted verification pending |
| tar-create-directory | Bounded uncompressed TAR creation from regular files; filesystem metadata omitted | Implemented; tests added; hosted verification pending |
| tar-extract-entry / tar-extract-all | Selected-file or new-directory extraction of regular files/directories; traversal, links, special entries and overwrite rejected | Implemented; tests added; hosted verification pending |
| manifest-create / manifest-verify | Versioned SHA-256 manifest using root-relative Unicode paths | Linux match/change/missing and traversal fixtures tested |
| age-keygen | Generate an X25519 age identity; private identity is saved to a new key file | Linux fixture and owner-only Unix permissions tested |
| age-encrypt / age-decrypt | Stream age X25519 file encryption and authenticated decryption, up to 4 GiB | Linux round-trip, wrong-key, tampering, collision and symlink fixtures tested |
| signature-keygen / signature-protect-key / signature-export-public / signature-create / signature-verify | Ed25519 keys with age-scrypt protected schema-v2 seeds; backward-compatible schema-v1 plaintext import; stable v1 detached signature envelope | Protected-key roundtrip, wrong-passphrase, tamper, migration, no-overwrite and permission fixtures implemented; targeted and hosted tests pending |
| zip-test | Stored and Deflate ZIP checksum tests without extraction | Linux fixture-tested |

See section 04-07 and 10 of the master specification for complete targets.
