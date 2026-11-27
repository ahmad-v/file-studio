# Dependencies

Cargo manifests list the exact direct requirements. The committed lockfile records the resolved versions and registry checksums. Builds use Rust 1.89.0 from `rust-toolchain.toml`; this minimum is required by the bundled `rusqlite 0.43.0` persistent catalogue engine. The CI checkout action is pinned to its upstream v4.2.2 commit.

File encryption uses the exact direct dependency `age 0.11.5` (`MIT OR Apache-2.0`) with default features disabled. It implements the established age X25519 file format; the application does not implement cryptographic primitives. This X25519-only integration avoids enabling the upstream crate's unrelated OpenSSH and newer recipient features. The lockfile records its transitive dependency checksums. Review the generated CI license inventory and update this summary if the resolved graph changes.

A preliminary RustSec review used advisory database revision `c9f6c91a44dbad9d71742329e9df061279f9c4be`. The pinned Localwright revision uses Iced’s Tiny Skia software renderer and removes the affected `lru 0.12.5` dependency path (RUSTSEC-2026-0002 and RUSTSEC-2026-0253). Full license review, SBOM and native dependency review remain open.

The persistent catalogue uses `rusqlite 0.43.0` with its bundled SQLite source (`libsqlite3-sys 0.40.0`) and `tempfile 3.19.1` for private staging before no-clobber publication. Rusqlite is MIT; SQLite's upstream project is public domain. Bundling avoids an external SQLite installation and fixes the supported Rust minimum at 1.89. Catalogue databases are capped at 64 MiB, opened read-only for search/history, and versioned with application and schema IDs. Final license/native asset review remains open.

On 2026-11-27, `cargo +1.89.0 audit --file Cargo.lock` found no vulnerability advisories. It reported eight unmaintained crates with no fixed versions: `basic-toml 0.1.10`, `instant 0.1.13`, `pin-utils 0.1.1`, `proc-macro-error2 2.0.1`, `rustybuzz 0.14.1`, and `ttf-parser` 0.20.0, 0.21.1 and 0.25.1. These remain dependency-monitoring items; the current advisory output contained no security vulnerability finding.
