# Format and operation compatibility

No capability is marked device-verified or released. Previous hosted jobs passed Linux and Windows targets; the current SQLite catalogue head awaits its native matrix. The machine-readable registry is a development inventory, not an advertised capability list.

| Operation | Route | Evidence status |
|---|---|---|
| catalog-compare | Compare JSON inventories or latest SQLite catalogue snapshots by path and size | Linux fixture-tested |
| catalog-history | Read the latest 100 SQLite scan snapshots without accessing original paths | Linux integration fixture-tested |
| catalog-refresh | Append schema-v2 full scans; classify path additions, size changes and removals only for matching Unix filesystem/root identity; use full-rescan fallback on Windows and other non-Unix targets | Implementation and focused tests added; hosted verification pending |
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
| manifest-create / manifest-verify | Versioned SHA-256 manifest using root-relative Unicode paths | Linux match/change/missing and traversal fixtures tested |
| age-keygen | Generate an X25519 age identity; private identity is saved to a new key file | Linux fixture and owner-only Unix permissions tested |
| age-encrypt / age-decrypt | Stream age X25519 file encryption and authenticated decryption, up to 4 GiB | Linux round-trip, wrong-key, tampering, collision and symlink fixtures tested |
| zip-test | Stored and Deflate ZIP checksum tests without extraction | Linux fixture-tested |

See section 04-07 and 10 of the master specification for complete targets.
