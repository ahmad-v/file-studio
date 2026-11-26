#![forbid(unsafe_code)]
use localwright_core::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};
pub const OPERATIONS: &[Operation] = &[
    Operation {
        id: "inspect",
        label: "Inspect",
        hint: "Read a regular file and compute SHA-256 and BLAKE3. Optional new JSON output.",
    },
    Operation {
        id: "verify",
        label: "Verify checksum",
        hint: "Enter sha256=HEX or blake3=HEX using 64 hex digits. Optional new JSON output on match.",
    },
    Operation {
        id: "scan",
        label: "Scan",
        hint: "Read-only recursive directory inventory. Output new JSON or CSV; symbolic links are skipped.",
    },
];
fn identify(b: &[u8]) -> &'static str {
    if b.starts_with(b"%PDF-") {
        "application/pdf"
    } else if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if b.starts_with(b"\xff\xd8\xff") {
        "image/jpeg"
    } else if b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") {
        "application/zip"
    } else if b.starts_with(b"\x7fELF") {
        "application/x-elf"
    } else if b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WAVE") {
        "audio/wav"
    } else {
        "unknown"
    }
}
fn inspect(p: &Path, j: &Job) -> Result<Value> {
    let before = fs::symlink_metadata(p)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Error::input("Expected regular non-symlink file"));
    }
    let mut f = fs::File::open(p)?;
    let opened = f.metadata()?;
    if !opened.is_file() {
        return Err(Error::input("Not regular file"));
    }
    let mut sha = Sha256::new();
    let mut b3 = blake3::Hasher::new();
    let mut buf = [0u8; 65536];
    let mut total = 0u64;
    let mut kind = "unknown";
    loop {
        j.check()?;
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if total == 0 {
            kind = identify(&buf[..n]);
        }
        total += n as u64;
        if total > before.len() {
            return Err(Error::input("File grew during inspection"));
        }
        sha.update(&buf[..n]);
        b3.update(&buf[..n]);
        j.progress(total, before.len());
    }
    let after = f.metadata()?;
    if total != before.len()
        || after.len() != before.len()
        || before.modified()? != after.modified()?
        || opened.modified()? != before.modified()?
    {
        return Err(Error::input("File changed during inspection"));
    }
    Ok(
        json!({"schema_version":1,"bytes":total,"signature":kind,"sha256":format!("{:x}",sha.finalize()),"blake3":b3.finalize().to_hex().to_string()}),
    )
}
fn verify(path: &Path, parameter: &str, job: &Job) -> Result<Value> {
    let (algorithm, expected) = parameter
        .split_once('=')
        .ok_or_else(|| Error::input("Expected sha256=HEX or blake3=HEX"))?;
    let algorithm = algorithm.trim().to_ascii_lowercase();
    let expected = expected.trim();
    if !matches!(algorithm.as_str(), "sha256" | "blake3") {
        return Err(Error::input("Choose sha256 or blake3"));
    }
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::input("Expected a 64-digit hexadecimal checksum"));
    }

    let inspection = inspect(path, job)?;
    let actual = inspection[algorithm.as_str()]
        .as_str()
        .ok_or_else(|| Error::input("Checksum unavailable"))?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(Error::input(format!(
            "{algorithm} checksum mismatch: expected {expected}, computed {actual}"
        )));
    }
    Ok(json!({
        "schema_version": 1,
        "algorithm": algorithm,
        "checksum": actual,
        "matched": true,
        "bytes": inspection["bytes"],
    }))
}
fn scan(root: &Path, j: &Job) -> Result<Vec<Value>> {
    let m = fs::symlink_metadata(root)?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(Error::input("Choose a non-symlink directory"));
    }
    let mut stack = vec![(root.to_path_buf(), 0)];
    let mut rows = vec![];
    let mut count = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        j.check()?;
        if depth > 64 {
            return Err(Error::input("Directory depth exceeds 64"));
        }
        for entry in fs::read_dir(dir)? {
            j.check()?;
            let e = entry?;
            let p = e.path();
            let m = fs::symlink_metadata(&p)?;
            count += 1;
            if count > 10000 {
                return Err(Error::input("Scan limit: 10,000 entries"));
            }
            if m.file_type().is_symlink() {
                continue;
            }
            if m.is_dir() {
                stack.push((p, depth + 1));
            } else if m.is_file() {
                let relative = p
                    .strip_prefix(root)
                    .map_err(|_| Error::input("Path escaped scan root"))?;
                let relative = relative.to_str().ok_or_else(|| {
                    Error::input("Non-Unicode path cannot be represented in report")
                })?;
                rows.push(json!({"path":relative,"bytes":m.len()}));
            }
        }
    }
    rows.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(rows)
}
fn safe_cell(s: &str) -> String {
    if s.trim_start().starts_with(['=', '+', '-', '@']) || s.starts_with(['\t', '\r', '\n']) {
        format!("'{s}")
    } else {
        s.into()
    }
}
pub fn handle(r: Request, j: Job) -> Result<Outcome> {
    j.check()?;
    let value = match r.operation.as_str() {
        "inspect" => inspect(&r.input, &j)?,
        "verify" => verify(&r.input, &r.parameter, &j)?,
        "scan" => json!({"schema_version":1,"files":scan(&r.input,&j)?}),
        _ => return Err(Error::input("Unknown operation")),
    };
    let mut written = None;
    let encoded = serde_json::to_string_pretty(&value)?;
    if !r.output.as_os_str().is_empty() {
        j.check()?;
        match r.output.extension().and_then(|s| s.to_str()) {
            Some("json") => write_bytes(&r.output, encoded.as_bytes())?,
            Some("csv") if r.operation == "scan" => write_new(&r.output, |f| {
                let mut w = csv::Writer::from_writer(f);
                w.write_record(["path", "bytes"])
                    .map_err(|e| Error::input(e.to_string()))?;
                for row in value["files"].as_array().unwrap() {
                    j.check()?;
                    w.write_record([
                        safe_cell(row["path"].as_str().unwrap()),
                        row["bytes"].to_string(),
                    ])
                    .map_err(|e| Error::input(e.to_string()))?;
                }
                w.flush()?;
                Ok(())
            })?,
            _ if r.operation == "scan" => return Err(Error::input("Choose .json or .csv")),
            _ => return Err(Error::input("Choose .json output")),
        };
        written = Some(r.output);
    }
    let preview = if encoded.len() > 24000 {
        format!(
            "{}\n[Preview truncated]",
            encoded.chars().take(6000).collect::<String>()
        )
    } else {
        encoded
    };
    Ok(Outcome {
        preview,
        written,
        warnings: vec![if r.operation == "verify" {
            "A match verifies integrity against the supplied checksum. Use a trusted source for the checksum.".into()
        } else {
            "Signature detection is limited; scan paths may contain sensitive information.".into()
        }],
        ..Outcome::default()
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_vector_and_scan() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("é.txt");
        fs::write(&p, b"abc").unwrap();
        let v = inspect(&p, &Job::new()).unwrap();
        assert_eq!(
            v["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            v["blake3"],
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        assert_eq!(scan(d.path(), &Job::new()).unwrap().len(), 1);
        let output = d.path().join("report.csv");
        handle(
            Request {
                operation: "scan".into(),
                input: d.path().into(),
                output: output.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert!(fs::read_to_string(output).unwrap().contains("é.txt,3"));
    }
    #[test]
    fn signatures() {
        assert_eq!(identify(b"%PDF-1.7"), "application/pdf");
        assert_eq!(identify(b"abc"), "unknown");
    }

    #[test]
    fn verify_checksums_and_reject_mismatch_without_writing() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("sample.txt");
        let output = directory.path().join("verified.json");
        fs::write(&input, b"abc").unwrap();
        let request = |parameter: &str| Request {
            operation: "verify".into(),
            input: input.clone(),
            output: output.clone(),
            parameter: parameter.into(),
            ..Request::default()
        };
        let wrong = format!("sha256={}", "0".repeat(64));
        let error = handle(request(&wrong), Job::new()).unwrap_err();
        assert!(error.message.contains("checksum mismatch"));
        assert!(!output.exists());
        assert!(handle(request("sha256=abc"), Job::new()).is_err());
        assert!(!output.exists());

        let sha256 = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        handle(request(&format!(" SHA256 = {sha256} ")), Job::new()).unwrap();
        let report: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(report["checksum"], sha256.to_ascii_lowercase());
        assert_eq!(report["matched"], true);
        assert_eq!(report["bytes"], 3);

        let blake3 = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";
        let report = verify(&input, &format!("blake3={blake3}"), &Job::new()).unwrap();
        assert_eq!(report["algorithm"], "blake3");
        assert_eq!(report["checksum"], blake3);
    }
}
