# Verification evidence

Static checks performed on source artifacts only:

- file-studio: specification exact; TOML/JSON/YAML/CFF syntax, Python AST, XML/SVG/WiX well-formedness passed (not schema validation).
- file-studio: exact sibling dependency paths/version and 15 unique packaging rows passed.
- File fixture: independent Python SHA-256 known vector passed.
- file-studio: packaging architecture helper accepted synthetic ARM64 PE header and rejected x64 mismatch (not an executable test).

No Rust compilation or runtime tests executed. Cargo/rustc not installed; DNS lookup of static.rust-lang.org and index.crates.io failed. CI, package builds, signing, SBOM, license and security review remain pending.
