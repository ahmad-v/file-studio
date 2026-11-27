# Offline manual | File Studio

Development source only. Launch the GUI after compiling. Choose an operation, enter local input path and a new output path where needed, set the parameter as described under the operation selector, then Run. Status and errors are shown below. Cancel requests cooperative cancellation. The draft editor accepts transcript or plain text. Choose a theme to change workbench colors and control borders. UI scale adjusts the controls from 80% to 300% and remembers your appearance choices when you reopen the app. Paths are manually typed in this increment; native dialogs and full accessibility remain pending.

- `duplicates`: Groups matching-size files by BLAKE3, with a 1 GiB candidate read budget. Review results before deciding what to keep.
- `directory-usage`: Reports logical file sizes by top-level directory. Symlinks are skipped and hard links are counted by name.
- `inspect`: Signature subset, SHA-256/SHA-512/BLAKE3; JSON.
- `verify` checks the input against a SHA-256, SHA-512, or BLAKE3 checksum. Enter `sha256=HEX` or `blake3=HEX` in the operation parameter, using 64 hexadecimal digits, or `sha512=HEX` using 128 digits. Obtain the checksum from a trusted source. Leave the output blank for a preview or give it a new `.json` path for a report. A mismatch reports an error and creates no output.
- `age-keygen` creates a new age X25519 identity file at the chosen output path and displays its public recipient key. The saved file is private key material and has no passphrase protection. On Unix it is written with owner-only permissions. On Windows, identity files must be saved under your user profile and inherit that directory's access controls. Keep a secure backup and do not share the identity file.
- `age-encrypt` encrypts a regular file to the age X25519 public recipient key in Parameter and writes a new `.age` file. `age-decrypt` reads a regular age file and writes decrypted bytes to a new output path; enter the identity file path in Parameter. Both routes stream up to 4 GiB. On Windows, decrypted output must be saved under your user profile. Decryption publishes output only after the age stream authenticates successfully. Wrong keys, tampering, and collisions create no output.
- `zip-list`: List ZIP entries and declared sizes. Optional new JSON output. Member data is never expanded.
- `scan`: Bounded directory inventory; JSON/CSV.

To verify the bundled sample from the command line:

```sh
cargo run --locked --no-default-features -- --cli verify tests/fixtures/abc.txt "" sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Limitations: Signature identification is a limited prefix test, not exhaustive or format validation. Age encryption does not prove who sent a file, and the generated identity is not passphrase-protected. The app does not yet create or verify digital signatures. Scanning aborts on unreadable entries; no persistent volume catalogue, broad metadata sanitation or backup. Archive creation omits empty directories and filesystem metadata. A locally stored checksum manifest can be edited by anyone who can modify it.

No output overwrite is allowed. No accounts, ads, telemetry or runtime downloads are intended. Do not use this unverified snapshot with valuable or hostile input. Citation and donations are voluntary.

Use `zip-test` to verify stored and Deflate entry data without extraction. It accepts archives up to 32 MiB and 4,096 entries, with a 32 MiB expansion limit per entry and 128 MiB per archive. Successful checks confirm decode and internal checksums. Extraction safety and authenticity require separate checks.

Use `hex-preview` with an optional `offset,length` parameter. The default is 256 bytes from offset zero. The maximum is 1,024 bytes. Prefix the offset with `0x` to enter hexadecimal. The report shows printable ASCII beside the hex values and may contain sensitive bytes.

Use `zip-create` with one regular file up to 16 MiB and a new `.zip` path. Leave the parameter blank to use the input filename, or enter a portable ASCII filename for the entry. This route preserves file bytes and uses a single flat entry. Ownership, original timestamps and extended attributes are omitted.

Use `zip-create-directory` with a directory and a new `.zip` path to archive up to 4,096 regular files, 32 MiB each and 128 MiB total. Symbolic links and empty directories are skipped. The operation checks source sizes and modification times while reading. Use `zip-extract-all` with a ZIP and a new destination folder. It rejects traversal, duplicate paths, links, encrypted or special files, and expansion beyond the same limits. It reserves the destination directory exclusively and creates each output file without overwriting. If extraction fails, the partial destination created by that attempt is removed. Review extracted content before opening it.

Use `manifest-create` with a directory and a new JSON output outside that directory. It records a schema version, SHA-256 algorithm, relative Unicode paths, byte sizes and hashes for up to 10,000 files and 1 GiB. `manifest-verify` takes the saved manifest as Input and its root directory as Parameter. It reports matching, changed and missing files; it rejects absolute/traversal paths, duplicate paths and symlinked path components. A checksum manifest does not prove who authored it.

To extract one file, first use `zip-list` and read its one-based entry number. Pass that number to `zip-extract-entry` and choose a new output file. Unsafe entry paths, symlinks, nonregular entries, CRC errors, files over 32 MiB expanded and output collisions are rejected.

Use `png-metadata` to count chunk types and identify removable metadata without reading tag values. Use `png-strip-metadata` with a new `.png` output to omit `tEXt`, `zTXt`, `iTXt`, and `eXIf` chunks. The report shows counts before and after. Image data and chunks such as ICC profiles remain. Treat the output as a selective metadata cleanup and review its contents before sharing.

To search while a source drive is unavailable, save a scan as JSON. Later use `catalog-search` with the saved inventory as Input and a path fragment as Parameter. Search matches Unicode-lowercased text and does not access the paths. A new JSON output is optional. Results reflect the original scan and may contain sensitive filenames.

## Additional operations

- `catalog-compare`. Open the earlier catalog JSON and enter the later catalog path. The report lists added, removed, and size-changed paths. A same-size match can still have different contents.
- `file-times`. Open a regular file. Times are reported in Unix epoch milliseconds. Unavailable timestamps appear as null.
