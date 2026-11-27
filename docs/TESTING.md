# Testing

Rust unit tests and synthetic fixtures cover the current bounded operations. Run `cargo test --locked` for the GUI-default suite and `cargo test --locked --no-default-features` for headless tests. The quick Check workflow runs the default Linux x64 suite. Use Integration for the combined default/headless suites and virtual-display launch; use Native platform validation at integration milestones and for platform-sensitive changes. Test malformed input and independent reader round trips. For GUI verify keyboard traversal, screen readers, high contrast, scaling, responsive processing and cancellation. Test with network disabled; inspect outbound calls and private-runtime resolution. No screenshot or claim of visual fidelity until a real app runs.

See tests/fixtures/README.md for source and expected outcomes; unit tests use temporary directories. Compare exported files with independent readers and confirm original bytes are unchanged.

All source and test execution must be recorded with commit, target, command, exit status and log URL. Review security risks in docs/STATUS.md before opening hostile files. Do not distribute untested packages.
