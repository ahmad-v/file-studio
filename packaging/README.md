# Packaging preparation

The target matrix retains all 15 combinations. The installable formats in this matrix still require device validation. This is an unsigned development payload. The experimental driver checks native host and executable architecture, requires Cargo.lock and refuses packaging until the maintainer approves the candidate application identity in config.json. It does not itself prove that a lockfile, dependencies or output are safe.

| Recipe | Status |
|---|---|
| Windows portable ZIP x64/ARM64 | Driver present; unverified |
| Windows MSI x64/ARM64 | WiX source candidate; unverified |
| Windows offline setup EXE x64/ARM64 | Burn template only; native tool validation blocked |
| Linux DEB/RPM x64/ARM64 | Driver present; dependencies and distro QA pending |
| Linux AppImage x64/ARM64 | Driver present; reviewed pinned tool/runtime and ABI testing required |
| Linux Flatpak x64/ARM64 | Manifest template; vendor source and pinned runtime required |
| macOS ARM64 DMG | APP/DMG driver; ad hoc signing, not notarized, unverified |

Installable packages are not currently assembled by CI. The identity in `config.json` remains unapproved, and the package driver refuses to run until that is resolved. RPM, WiX, AppImage and Flatpak tooling also need separate audited provisioning and validation. No public release workflow is provided. The Flatpak template omits network permission and grants no blanket filesystem access; portal integration is missing. These recipes are not release ready.

Windows MSI and EXE must use the same product identity and payload, separately verify repair/upgrade/uninstall and architecture, and embed all payloads. Candidate application ID `org.localwright.FileStudio` is not a verified owner namespace or trademark. Product GUID generated deterministically as a proposed identifier, not an existing registered product. Review before fixing identity. Linux and macOS require real-device validation. No signing keys, service accounts or secrets are included.

## Manually triggered portable previews

The **Distribution preview** workflow is manually triggered. It builds an optimized binary on each of the five native targets, assembles and extracts an unsigned portable archive, runs CLI help from the extracted payload, and uploads the preview with SHA-256 checksums for seven days. These temporary artifacts are for evaluation and are not installable release packages. Linux may require system libraries, and macOS Gatekeeper may block an unsigned executable.

The **Check** workflow is the quick Linux x64 development gate and avoids release builds. **Integration** runs default and headless tests plus a virtual-display GUI launch when manually dispatched or when a PR receives the `integration` label. **Native platform validation** runs the five-target build and test matrix when manually dispatched or when a PR receives the `native-validation` label. **Security and dependency review** runs weekly and on demand; it audits the locked Rust graph and uploads CycloneDX and declared-license/notice inventory evidence. The generated license inventory is not a license approval.
