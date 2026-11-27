# Dependencies

Cargo manifests list the exact direct requirements. The committed lockfile records the resolved versions and registry checksums. Builds use Rust 1.88.0 from `rust-toolchain.toml`. The CI checkout action is pinned to its upstream v4.2.2 commit.

File encryption uses the exact direct dependency `age 0.11.5` (`MIT OR Apache-2.0`) with default features disabled. It implements the established age X25519 file format; the application does not implement cryptographic primitives. This X25519-only integration avoids enabling the upstream crate's unrelated OpenSSH and newer recipient features. The lockfile records its transitive dependency checksums. Review the generated CI license inventory and update this summary if the resolved graph changes.

A preliminary RustSec review used advisory database revision `c9f6c91a44dbad9d71742329e9df061279f9c4be`. The pinned Localwright revision uses Iced’s Tiny Skia software renderer and removes the affected `lru 0.12.5` dependency path (RUSTSEC-2026-0002 and RUSTSEC-2026-0253). Full license review, SBOM and native dependency review remain open.
