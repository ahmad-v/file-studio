# File Studio

File inspection and integrity. This is a development snapshot (0.1.0-alpha.1), not a verified release or installer.

This independent studio uses Localwright at source level. There is no separate mandatory Localwright installation.

## What is in this snapshot

- File inspection, metadata and timestamps, bounded hexadecimal preview, SHA-256/SHA-512/BLAKE3 verification, and PNG metadata operations.
- Directory inventories and saved-catalogue search, duplicate candidates, usage reports, versioned SHA-256 manifests, safe ZIP routes, and age file encryption.
- SQLite catalogues retain scan history and support disconnected snapshot search. Linux refreshes compare only when the filesystem-device/root-inode identity matches; other targets record full-rescan baselines. Refreshes still traverse the complete directory.
- The native Catalogue workspace opens a saved SQLite catalogue, searches and paginates matching paths, reviews recent scans, and appends a fresh snapshot from a selected folder. General processing routes remain available in the Operations page.

Linux fixture and CLI evidence is recorded in [status](docs/STATUS.md) and [verification](docs/VERIFICATION.md). These features are not a verified release: native device, installer lifecycle, broader metadata formats, signatures, incremental cataloguing, and some filesystem race cases remain open. Cross-platform stable identity is not implemented; identity-based deltas are currently Linux-only.

The project is intended to remain free, local and offline, without tracking, advertising, subscriptions or premium features. See [the manifesto](MANIFESTO.md) for the motivation behind it.

## Development

See [build notes](docs/BUILD.md), [status](docs/STATUS.md), [architecture](docs/ARCHITECTURE.md) and [manual](docs/MANUAL.md). The complete [master specification](MASTER_SPECIFICATION.md) defines the remaining requirements. Linux tests and a prior five-target CI run are documented; current five-target verification is an explicit integration workflow, and device/installer acceptance remains open.

## Citation and contributions

If the software is useful in your research, please consider citing its version once a verified release and actual repository URL exist. See `CITATION.cff`. No DOI has been assigned. Code, testing, translations and documentation are welcome. No donation account has been configured.

Original code candidate license: MIT OR Apache-2.0, pending maintainer approval and dependency review. AI-assisted source requires human review before publication.
