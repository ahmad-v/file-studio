# Format and operation compatibility

Nothing is verified on a native target. The machine-readable registry is a development inventory, not an advertised capability list.

| Operation | Route | Evidence status |
|---|---|---|
| catalog-compare | Compare paths and sizes in saved inventories | Linux fixture-tested |
| file-times | Read creation, modification and access timestamps | Linux fixture-tested |
| png-metadata / png-strip-metadata | PNG chunk inspection and removal of text and EXIF from a copy | Linux fixture-tested |
| hex-preview | Bounded offset window with hex and printable ASCII | Linux fixture and CLI-tested |
| inspect | Signature subset, SHA-256/BLAKE3; JSON | implemented-unverified |
| catalog-search | Search a saved version 1 inventory by path text | Linux unit fixture and CLI-tested |
| scan | Bounded directory inventory; JSON/CSV | implemented-unverified |
| zip-extract-entry | Extract one numbered regular entry to a chosen path | Linux fixture and CLI-tested |
| zip-create | One regular file as a Deflate ZIP with a portable entry name | Linux fixture and CLI-tested |
| zip-create-directory | Regular files in a directory tree to Deflate ZIP; empty directories and filesystem metadata omitted | Linux round-trip fixture-tested |
| zip-extract-all | Bounded regular files/directories to a new folder; links, traversal and collisions rejected | Linux round-trip and malicious-path fixture-tested |
| manifest-create / manifest-verify | Versioned SHA-256 manifest using root-relative Unicode paths | Linux match/change/missing and traversal fixtures tested |
| zip-test | Stored and Deflate ZIP checksum tests without extraction | Linux fixture-tested |

See section 04-07 and 10 of the master specification for complete targets.
