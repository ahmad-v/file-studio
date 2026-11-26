# Format and operation compatibility

Nothing is verified on a native target. The machine-readable registry is a development inventory, not an advertised capability list.

| Operation | Route | Evidence status |
|---|---|---|
| inspect | Signature subset, SHA-256/BLAKE3; JSON | implemented-unverified |
| scan | Bounded directory inventory; JSON/CSV | implemented-unverified |
| zip-test | Stored and Deflate ZIP checksum tests without extraction | Linux fixture-tested |

See section 04-07 and 10 of the master specification for complete targets.
