# Architecture

File Studio: File inspection and integrity.

Localwright core contains serde-based domain contracts, request/response, capability and engine descriptors, job cancellation, bounded reads, no-clobber output and settings. It has no Iced dependency. Localwright UI is an optional dependency of the studios and provides a generic native operation workbench. It dispatches a single job to a background thread and receives the structured outcome through a channel. The same handler runs through the CLI. Studio processing lives in its own crate. No local server, system engine lookup or runtime network client is intentionally implemented.

Source contracts version 0.1.0-alpha.1; pre-1.0 API is unstable. Use exact shared revision after import. New breaking changes require migration notes and all four consumer checks. Candidate Rust minimum 1.85 (untested), toolchain 1.88.0 (untested). No promise of ABI stability. Current settings schema 1. Request and outcome are internal alpha interchange, not stable project file formats.

The native `inspect` operation combines the hash/signature pass with available file timestamps, a 64-byte hexadecimal/ASCII sample, and PNG chunk counts for valid PNG inputs within the PNG parser's 32 MiB bound. The sample may contain sensitive content; PNG tag values are not decoded. Other format-specific properties remain unavailable. Signature identification is a limited prefix test, not exhaustive or format validation. Scanning aborts on unreadable entries; no persistent volume catalogue, broad metadata sanitation or backup. File metadata comparison cannot detect every concurrent modification or path race.
