use localwright_core::{Job, Request};
use serde_json::{json, Value};
use std::fs;

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
