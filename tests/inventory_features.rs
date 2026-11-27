use localwright_core::{Job, Request};
use serde_json::{json, Value};
use std::{fs, io::Write};

#[test]
fn compares_saved_inventory_sizes_without_opening_any_listed_paths() {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    fs::write(&before, r#"{"schema_version":1,"files":[{"path":"old","bytes":1},{"path":"Café","bytes":2},{"path":"same","bytes":3}]}"#).unwrap();
    fs::write(&after, r#"{"schema_version":1,"files":[{"path":"new","bytes":1},{"path":"Café","bytes":4},{"path":"same","bytes":3}]}"#).unwrap();
    let request = Request {
        operation: "catalog-compare".into(),
        input: before,
        parameter: after.to_str().unwrap().into(),
        ..Request::default()
    };
    let result = file_studio::handle(request.clone(), Job::new()).unwrap();
    let report: Value = serde_json::from_str(&result.preview).unwrap();
    assert_eq!(
        report,
        json!({"schema_version":1,"added":[{"path":"new","bytes":1}],"removed":[{"path":"old","bytes":1}],"size_changed":[{"path":"Café","before_bytes":2,"after_bytes":4}],"same_size":1})
    );
    fs::write(
        after,
        r#"{"schema_version":1,"files":[{"path":"new","bytes":1},{"path":"new","bytes":2}]}"#,
    )
    .unwrap();
    assert!(file_studio::handle(request, Job::new()).is_err());
}

#[test]
fn timestamp_report_reads_metadata_and_rejects_directories() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let output = dir.path().join("report.json");
    fs::write(&input, b"abc").unwrap();
    let request = Request {
        operation: "file-times".into(),
        input,
        output: output.clone(),
        ..Request::default()
    };
    file_studio::handle(request.clone(), Job::new()).unwrap();
    let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(report["bytes"], 3);
    assert!(report["modified_unix_ms"].is_i64());
    assert!(file_studio::handle(
        Request {
            input: dir.path().into(),
            ..request
        },
        Job::new()
    )
    .is_err());
}

#[test]
fn checksum_manifest_detects_changes_missing_files_and_unsafe_paths() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/a.txt"), b"trusted bytes").unwrap();
    fs::write(root.join("b.txt"), b"second").unwrap();
    let manifest = dir.path().join("manifest.json");
    file_studio::handle(
        Request {
            operation: "manifest-create".into(),
            input: root.clone(),
            output: manifest.clone(),
            ..Request::default()
        },
        Job::new(),
    )
    .unwrap();

    fs::write(root.join("nested/a.txt"), b"changed bytes").unwrap();
    fs::remove_file(root.join("b.txt")).unwrap();
    fs::write(root.join("new.txt"), b"new file").unwrap();
    let result = file_studio::handle(
        Request {
            operation: "manifest-verify".into(),
            input: manifest.clone(),
            parameter: root.to_str().unwrap().into(),
            ..Request::default()
        },
        Job::new(),
    )
    .unwrap();
    let report: Value = serde_json::from_str(&result.preview).unwrap();
    assert_eq!(report["verified"], 0);
    assert_eq!(report["changed"], json!(["nested/a.txt"]));
    assert_eq!(report["missing"], json!(["b.txt"]));

    fs::write(&manifest, r#"{"schema_version":1,"algorithm":"sha256","files":[{"path":"../outside","bytes":0,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}"#).unwrap();
    assert!(file_studio::handle(
        Request {
            operation: "manifest-verify".into(),
            input: manifest,
            parameter: root.to_str().unwrap().into(),
            ..Request::default()
        },
        Job::new()
    )
    .is_err());
}

#[test]
fn directory_zip_roundtrip_and_archive_traversal_rejection() {
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(source.join("sub")).unwrap();
    fs::write(source.join("root.txt"), b"root payload").unwrap();
    fs::write(source.join("sub/cafe.txt"), "café".as_bytes()).unwrap();
    let archive = dir.path().join("bundle.zip");
    file_studio::handle(
        Request {
            operation: "zip-create-directory".into(),
            input: source,
            output: archive.clone(),
            ..Request::default()
        },
        Job::new(),
    )
    .unwrap();
    let extracted = dir.path().join("extracted");
    file_studio::handle(
        Request {
            operation: "zip-extract-all".into(),
            input: archive,
            output: extracted.clone(),
            ..Request::default()
        },
        Job::new(),
    )
    .unwrap();
    assert_eq!(
        fs::read(extracted.join("root.txt")).unwrap(),
        b"root payload"
    );
    assert_eq!(
        fs::read_to_string(extracted.join("sub/cafe.txt")).unwrap(),
        "café"
    );
    assert!(file_studio::handle(
        Request {
            operation: "zip-extract-all".into(),
            input: dir.path().join("bundle.zip"),
            output: extracted.clone(),
            ..Request::default()
        },
        Job::new()
    )
    .is_err());
    assert_eq!(
        fs::read(extracted.join("root.txt")).unwrap(),
        b"root payload"
    );

    let malicious = dir.path().join("malicious.zip");
    let mut zip = ZipWriter::new(fs::File::create(&malicious).unwrap());
    zip.start_file(
        "../outside.txt",
        SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(b"unsafe").unwrap();
    zip.finish().unwrap();
    let rejected_output = dir.path().join("rejected");
    assert!(file_studio::handle(
        Request {
            operation: "zip-extract-all".into(),
            input: malicious,
            output: rejected_output.clone(),
            ..Request::default()
        },
        Job::new()
    )
    .is_err());
    assert!(!rejected_output.exists());
    assert!(!dir.path().join("outside.txt").exists());
}
