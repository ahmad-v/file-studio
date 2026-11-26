#![forbid(unsafe_code)]
mod png_metadata;
use localwright_core::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
pub const OPERATIONS: &[Operation] = &[
    Operation {
        id: "inspect",
        label: "Inspect",
        hint: "Read a regular file and compute SHA-256, SHA-512 and BLAKE3. Optional new JSON output.",
    },
    Operation {
        id: "png-metadata",
        label: "Inspect PNG metadata",
        hint: "Count PNG chunk types and identify removable text and EXIF chunks. Optional JSON output.",
    },
    Operation {
        id: "png-strip-metadata",
        label: "Remove PNG text and EXIF",
        hint: "Remove PNG text and EXIF chunks from a copy. Choose a new .png output.",
    },
    Operation {
        id: "hex-preview",
        label: "Hex preview",
        hint: "Enter offset,length in bytes (decimal offset or 0x hex offset). Default 0,256. Maximum 1,024 bytes. Optional JSON output.",
    },
    Operation {
        id: "verify",
        label: "Verify checksum",
        hint: "Enter sha256=HEX or blake3=HEX (64 digits), or sha512=HEX (128 digits). Optional new JSON output on match.",
    },
    Operation {
        id: "zip-list",
        label: "List ZIP contents",
        hint: "Inspect ZIP directory entries without expanding them. Optional new JSON output.",
    },
    Operation {
        id: "zip-test",
        label: "Test ZIP integrity",
        hint: "Read stored or deflated entries and verify their checksums without extracting. Optional new JSON output.",
    },
    Operation {
        id: "zip-extract-entry",
        label: "Extract one ZIP entry",
        hint: "Use the entry number shown by List ZIP contents. Extract one regular file to a new output path.",
    },
    Operation {
        id: "zip-create",
        label: "Create ZIP from a file",
        hint: "Compress one regular file to a new ZIP. Optionally enter a portable filename for the archive entry.",
    },
    Operation {
        id: "duplicates",
        label: "Find duplicate candidates",
        hint: "Group same-size files with matching BLAKE3 checksums. Optional new JSON output.",
    },
    Operation {
        id: "directory-usage",
        label: "Directory usage",
        hint: "Total regular-file sizes by top-level directory. Optional new JSON output.",
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
fn inspect(p: &Path, j: &Job, expected_size: Option<u64>) -> Result<Value> {
    let before = fs::symlink_metadata(p)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Error::input("Expected regular non-symlink file"));
    }
    if expected_size.is_some_and(|size| before.len() != size) {
        return Err(Error::input("A candidate changed since the directory scan"));
    }
    let mut f = fs::File::open(p)?;
    let opened = f.metadata()?;
    if !opened.is_file() {
        return Err(Error::input("Not regular file"));
    }
    let mut sha = Sha256::new();
    let mut sha512 = Sha512::new();
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
        sha512.update(&buf[..n]);
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
        json!({"schema_version":1,"bytes":total,"signature":kind,"sha256":format!("{:x}",sha.finalize()),"sha512":format!("{:x}",sha512.finalize()),"blake3":b3.finalize().to_hex().to_string()}),
    )
}
fn hex_preview(path: &Path, parameter: &str, job: &Job) -> Result<Value> {
    let (offset, length) = if parameter.trim().is_empty() {
        (0, 256)
    } else {
        let (offset, length) = parameter
            .split_once(',')
            .ok_or_else(|| Error::input("Expected offset,length"))?;
        let offset = offset.trim();
        let start = if let Some(hex) = offset
            .strip_prefix("0x")
            .or_else(|| offset.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
        } else {
            offset.parse()
        }
        .map_err(|_| Error::input("Invalid byte offset"))?;
        let length = length
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|length| (1..=1024).contains(length))
            .ok_or_else(|| Error::input("Byte length must be from 1 to 1,024"))?;
        (start, length)
    };
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() {
        return Err(Error::input("Expected a regular non-symlink file"));
    }
    let mut file = fs::File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.len() != before.len()
        || opened.modified()? != before.modified()?
    {
        return Err(Error::input("File changed before preview"));
    }
    if offset > opened.len() {
        return Err(Error::input("Byte offset is past the end of the file"));
    }
    job.check()?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; length.min((opened.len() - offset).try_into().unwrap_or(usize::MAX))];
    file.read_exact(&mut bytes)?;
    let after = file.metadata()?;
    if after.len() != opened.len() || after.modified()? != opened.modified()? {
        return Err(Error::input("File changed during preview"));
    }
    job.check()?;
    let rows = bytes
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex = chunk.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ");
            let ascii = chunk.iter().map(|&byte| match byte {
                b' '..=b'~' => char::from(byte),
                _ => '.',
            }).collect::<String>();
            json!({"offset_hex":format!("{:016x}", offset + (i * 16) as u64), "hex": hex, "ascii": ascii})
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"schema_version":1, "file_bytes":opened.len(), "bytes_displayed":bytes.len(), "rows":rows}),
    )
}

fn verify(path: &Path, parameter: &str, job: &Job) -> Result<Value> {
    let (algorithm, expected) = parameter
        .split_once('=')
        .ok_or_else(|| Error::input("Expected sha256=HEX, sha512=HEX or blake3=HEX"))?;
    let algorithm = algorithm.trim().to_ascii_lowercase();
    let expected = expected.trim();
    let digits = match algorithm.as_str() {
        "sha256" | "blake3" => 64,
        "sha512" => 128,
        _ => return Err(Error::input("Choose sha256, sha512 or blake3")),
    };
    if expected.len() != digits || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::input(format!(
            "Expected a {digits}-digit hexadecimal checksum"
        )));
    }

    let inspection = inspect(path, job, None)?;
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
fn open_zip(p: &Path, job: &Job) -> Result<zip::ZipArchive<std::io::Cursor<Vec<u8>>>> {
    const MAX_ENTRIES: usize = 4096;
    let bytes = read_bounded(p, 32 * 1024 * 1024)?;
    job.check()?;
    let archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|error| Error::input(format!("Invalid ZIP: {error}")))?;
    if archive.len() > MAX_ENTRIES {
        return Err(Error::new(ErrorKind::Limit, "ZIP entry limit exceeded"));
    }
    Ok(archive)
}

fn test_zip(p: &Path, job: &Job) -> Result<Value> {
    const MAX_UNCOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;
    const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
    let mut archive = open_zip(p, job)?;
    let mut total = 0u64;
    for index in 0..archive.len() {
        job.check()?;
        let mut member = archive.by_index(index).map_err(|error| {
            Error::input(format!("Cannot open ZIP entry {}: {error}", index + 1))
        })?;
        if member.size() > MAX_ENTRY_BYTES || member.size() > MAX_UNCOMPRESSED_BYTES - total {
            return Err(Error::new(ErrorKind::Limit, "ZIP expansion limit exceeded"));
        }
        let size = member.size();
        stream_zip_entry(&mut member, size, std::io::sink(), index + 1, job)?;
        total += size;
    }
    Ok(json!({"schema_version": 1, "entries_checked": archive.len(), "uncompressed_bytes": total}))
}

fn stream_zip_entry(
    mut reader: impl Read,
    size: u64,
    mut output: impl Write,
    number: usize,
    job: &Job,
) -> Result<()> {
    let mut total = 0;
    let mut buffer = [0u8; 32 * 1024];
    loop {
        job.check()?;
        let count = reader.read(&mut buffer).map_err(|error| {
            Error::input(format!(
                "ZIP entry {number} failed integrity checking: {error}"
            ))
        })?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > size {
            return Err(Error::input(format!(
                "ZIP entry {number} expands beyond its declared size"
            )));
        }
        output.write_all(&buffer[..count])?;
    }
    if total != size {
        return Err(Error::input(format!("ZIP entry {number} size mismatch")));
    }
    Ok(())
}

fn extract_zip_entry(input: &Path, output: &Path, parameter: &str, job: &Job) -> Result<Value> {
    const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
    let number = parameter
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|&n| n > 0)
        .ok_or_else(|| Error::input("Enter a positive ZIP entry number"))?;
    let mut archive = open_zip(input, job)?;
    let mut member = archive
        .by_index(number - 1)
        .map_err(|error| Error::input(format!("Cannot open ZIP entry {number}: {error}")))?;
    let name = member
        .name()
        .map_err(|error| Error::input(format!("Invalid ZIP entry name: {error}")))?;
    if member.is_dir()
        || member.is_symlink()
        || member
            .unix_mode()
            .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000))
    {
        return Err(Error::input("Choose a regular ZIP file entry"));
    }
    if member.enclosed_name().is_none()
        || name
            .split(['/', '\\'])
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || name.contains([':', '\0'])
    {
        return Err(Error::input("ZIP entry has an unsafe name"));
    }
    let size = member.size();
    if size > MAX_ENTRY_BYTES {
        return Err(Error::new(ErrorKind::Limit, "ZIP expansion limit exceeded"));
    }
    // The member name is reported only. Creation uses the user-selected path.
    let report =
        json!({"schema_version":1,"entry_number":number,"entry":name,"uncompressed_bytes":size});
    write_new(output, |file| {
        stream_zip_entry(&mut member, size, file, number, job)
    })?;
    Ok(report)
}

fn create_zip(input: &Path, output: &Path, parameter: &str, job: &Job) -> Result<Value> {
    const MAX_SOURCE: u64 = 16 * 1024 * 1024;
    if !output
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
    {
        return Err(Error::input("Choose .zip output"));
    }
    let name = if parameter.is_empty() {
        input
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::input("Enter a portable ZIP entry filename"))?
    } else {
        parameter
    };
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    if name.is_empty()
        || name.len() > 128
        || name.starts_with(['.', ' '])
        || name.ends_with(['.', ' '])
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._- ".contains(&byte))
        || reserved
    {
        return Err(Error::input(
            "ZIP entry must be a portable ASCII filename without directories",
        ));
    }
    let content = read_bounded(input, MAX_SOURCE)?;
    job.check()?;
    write_new(output, |file| {
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        archive
            .start_file(name, options)
            .map_err(|error| Error::input(error.to_string()))?;
        for chunk in content.chunks(64 * 1024) {
            job.check()?;
            archive.write_all(chunk)?;
        }
        archive
            .finish()
            .map_err(|error| Error::input(error.to_string()))?;
        job.check()
    })?;
    Ok(json!({"schema_version":1,"entry":name,"uncompressed_bytes":content.len()}))
}

fn list_zip(p: &Path, job: &Job) -> Result<Value> {
    let mut archive = open_zip(p, job)?;
    let mut names_bytes = 0usize;
    let mut entries = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        job.check()?;
        let member = archive
            .by_index_raw(index)
            .map_err(|error| Error::input(format!("Invalid ZIP entry: {error}")))?;
        let name = member
            .name()
            .map_err(|error| Error::input(format!("Invalid ZIP entry name: {error}")))?;
        names_bytes += name.len();
        if names_bytes > 256 * 1024 {
            return Err(Error::new(
                ErrorKind::Limit,
                "ZIP entry names exceed the report limit",
            ));
        }
        entries.push(json!({
            "number": index + 1,
            "name": name,
            "directory": member.is_dir(),
            "symlink": member.is_symlink(),
            "encrypted": member.encrypted(),
            "compressed_bytes": member.compressed_size(),
            "declared_bytes": member.size(),
        }));
    }
    Ok(json!({"schema_version":1,"entries":entries}))
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
fn directory_usage(root: &Path, job: &Job) -> Result<Value> {
    let mut total = 0u64;
    let mut root_bytes = 0u64;
    let mut directories = std::collections::BTreeMap::<String, u64>::new();
    let files = scan(root, job)?;
    for file in &files {
        job.check()?;
        let bytes = file["bytes"].as_u64().expect("scan reports a byte count");
        total = total
            .checked_add(bytes)
            .ok_or_else(|| Error::new(ErrorKind::Limit, "Directory byte total overflow"))?;
        let relative = Path::new(file["path"].as_str().expect("scan reports a path"));
        if let Some(parent) = relative.parent().filter(|p| !p.as_os_str().is_empty()) {
            let top = parent.components().next().expect("nonempty parent");
            *directories
                .entry(top.as_os_str().to_string_lossy().into_owned())
                .or_default() += bytes;
        } else {
            root_bytes += bytes;
        }
    }
    Ok(json!({
        "schema_version": 1,
        "regular_files": files.len(),
        "total_bytes": total,
        "root_bytes": root_bytes,
        "directories": directories,
    }))
}

fn duplicate_candidates(root: &Path, job: &Job) -> Result<Value> {
    let files = scan(root, job)?;
    let mut sizes = std::collections::BTreeMap::<u64, Vec<&str>>::new();
    for file in &files {
        job.check()?;
        let size = file["bytes"].as_u64().expect("scan reports a byte count");
        let path = file["path"].as_str().expect("scan reports a path");
        sizes.entry(size).or_default().push(path);
    }
    let mut read_budget = 1024 * 1024 * 1024u64;
    let mut groups = Vec::new();
    for (size, paths) in sizes.into_iter().filter(|(_, paths)| paths.len() > 1) {
        let bytes = size
            .checked_mul(paths.len() as u64)
            .and_then(|bytes| read_budget.checked_sub(bytes))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Limit,
                    "Duplicate scan exceeds 1 GiB of candidate files",
                )
            })?;
        read_budget = bytes;
        let mut hashes = std::collections::BTreeMap::<String, Vec<&str>>::new();
        for path in paths {
            job.check()?;
            let input = root.join(path);
            let entry = inspect(&input, job, Some(size))?;
            let digest = entry["blake3"].as_str().expect("inspection reports a hash");
            hashes.entry(digest.into()).or_default().push(path);
        }
        groups.extend(hashes.into_iter().filter(|(_, paths)| paths.len() > 1).map(
            |(digest, paths)| json!({"bytes_per_file": size, "blake3": digest, "paths": paths}),
        ));
    }
    Ok(json!({"schema_version": 1, "regular_files_scanned": files.len(), "groups": groups}))
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
        "inspect" => inspect(&r.input, &j, None)?,
        "png-metadata" => png_metadata::process(&r.input, None, &j)?,
        "png-strip-metadata" => {
            let report = png_metadata::process(&r.input, Some(&r.output), &j)?;
            return Ok(Outcome {
                preview: serde_json::to_string_pretty(&report)?,
                written: Some(r.output),
                warnings: vec!["Removed PNG text and EXIF chunks only. Image pixels, color profiles and other chunks remain and may contain sensitive information.".into()],
                ..Outcome::default()
            });
        }
        "hex-preview" => hex_preview(&r.input, &r.parameter, &j)?,
        "verify" => verify(&r.input, &r.parameter, &j)?,
        "duplicates" => duplicate_candidates(&r.input, &j)?,
        "directory-usage" => directory_usage(&r.input, &j)?,
        "zip-create" | "zip-extract-entry" => {
            let (value, warning) = if r.operation == "zip-create" {
                (
                    create_zip(&r.input, &r.output, &r.parameter, &j)?,
                    "ZIP creation preserves file contents. The archive does not carry source ownership, original timestamps or extended attributes.",
                )
            } else {
                (
                    extract_zip_entry(&r.input, &r.output, &r.parameter, &j)?,
                    "Extraction preserves entry bytes and uses the chosen output name. Review untrusted content before opening it.",
                )
            };
            return Ok(Outcome {
                preview: serde_json::to_string_pretty(&value)?,
                written: Some(r.output),
                warnings: vec![warning.into()],
                ..Outcome::default()
            });
        }
        "zip-list" => list_zip(&r.input, &j)?,
        "zip-test" => test_zip(&r.input, &j)?,
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
        } else if r.operation == "duplicates" {
            "Candidates share a size and BLAKE3 checksum. Review files before making any changes."
                .into()
        } else if r.operation == "directory-usage" {
            "Logical file sizes only. Hard links are counted per path, and symlinks are skipped."
                .into()
        } else if r.operation == "png-metadata" {
            "Reports PNG chunk types and counts without decoding image pixels or metadata values."
                .into()
        } else if r.operation == "hex-preview" {
            "The report contains raw file bytes. Review it before sharing.".into()
        } else if r.operation == "zip-test" {
            "Entry data integrity only. The report does not establish authenticity or extraction safety.".into()
        } else if r.operation == "zip-list" {
            "ZIP metadata only. Reported sizes are declarations and entry contents were not tested or extracted.".into()
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
        let v = inspect(&p, &Job::new(), None).unwrap();
        assert_eq!(
            v["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            v["blake3"],
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        let sha512 = concat!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(v["sha512"], sha512);
        let result = verify(&p, &format!("sha512={sha512}"), &Job::new()).unwrap();
        assert_eq!(result["matched"], true);
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
    fn lists_zip_entries_without_extracting_files() {
        use std::io::Write as _;
        let directory = tempfile::tempdir().unwrap();
        let zip_path = directory.path().join("input.zip");
        let mut writer = zip::ZipWriter::new(fs::File::create(&zip_path).unwrap());
        writer
            .start_file("../outside.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"abc").unwrap();
        writer.finish().unwrap();
        let listing = list_zip(&zip_path, &Job::new()).unwrap();
        assert_eq!(listing["entries"][0]["name"], "../outside.txt");
        assert_eq!(listing["entries"][0]["declared_bytes"], 3);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn directory_usage_counts_nested_files_under_their_top_level() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("group/nested")).unwrap();
        fs::write(root.path().join("root.txt"), b"123").unwrap();
        fs::write(root.path().join("group/nested/file.txt"), b"12345").unwrap();
        let usage = directory_usage(root.path(), &Job::new()).unwrap();
        assert_eq!(usage["root_bytes"], 3);
        assert_eq!(usage["total_bytes"], 8);
        assert_eq!(usage["directories"]["group"], 5);
    }

    #[test]
    fn reports_matching_files_without_grouping_different_same_size_files() {
        let root = tempfile::tempdir().unwrap();
        for (name, data) in [("first", b"abc"), ("second", b"abc"), ("different", b"xyz")] {
            fs::write(root.path().join(name), data).unwrap();
        }
        let report = duplicate_candidates(root.path(), &Job::new()).unwrap();
        assert_eq!(report["groups"].as_array().unwrap().len(), 1);
        assert_eq!(report["groups"][0]["paths"], json!(["first", "second"]));
    }

    #[test]
    fn hex_preview_reads_only_the_requested_window() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("sample.bin");
        let output = dir.path().join("preview.json");
        fs::write(&input, b"skip\x00ABC\x80").unwrap();
        let request = |parameter: &str| Request {
            operation: "hex-preview".into(),
            input: input.clone(),
            output: output.clone(),
            parameter: parameter.into(),
            ..Request::default()
        };
        assert!(handle(request("10,3"), Job::new()).is_err());
        assert!(handle(request("0,1025"), Job::new()).is_err());
        assert!(!output.exists());
        handle(request("0x4,10"), Job::new()).unwrap();
        let report: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(report["file_bytes"], 9);
        assert_eq!(report["bytes_displayed"], 5);
        assert_eq!(
            report["rows"][0],
            json!({
                "offset_hex": "0000000000000004",
                "hex": "00 41 42 43 80",
                "ascii": ".ABC."
            })
        );
        assert!(handle(request("0,1"), Job::new()).is_err());
    }

    #[test]
    fn extracts_only_a_selected_safe_entry() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.zip");
        let output = dir.path().join("chosen.bin");
        let mut archive = zip::ZipWriter::new(fs::File::create(&input).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("nested/safe.bin", options).unwrap();
        archive.write_all(b"safe").unwrap();
        archive.start_file("../escape.bin", options).unwrap();
        archive.write_all(b"unsafe").unwrap();
        archive
            .add_symlink("link", "nested/safe.bin", options)
            .unwrap();
        archive.finish().unwrap();
        let request = |parameter: &str| Request {
            operation: "zip-extract-entry".into(),
            input: input.clone(),
            output: output.clone(),
            parameter: parameter.into(),
            ..Request::default()
        };
        for invalid in ["0", "2", "3", "4"] {
            assert!(handle(request(invalid), Job::new()).is_err());
            assert!(!output.exists());
        }
        handle(request("1"), Job::new()).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"safe");
        assert!(handle(request("1"), Job::new()).is_err());
        assert!(!dir.path().join("nested").exists());
    }

    #[test]
    fn creates_a_single_file_zip_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.txt");
        let output = dir.path().join("archive.zip");
        fs::write(&input, b"hello archive").unwrap();
        let request = |parameter: &str| Request {
            operation: "zip-create".into(),
            input: input.clone(),
            output: output.clone(),
            parameter: parameter.into(),
            ..Request::default()
        };
        for invalid in ["../file", "a/b", "NUL.txt", "x.", "x ", "com1.txt"] {
            assert!(handle(request(invalid), Job::new()).is_err());
            assert!(!output.exists());
        }
        let result = handle(request(""), Job::new()).unwrap();
        assert_eq!(result.written.as_deref(), Some(output.as_path()));
        assert!(handle(request("second.txt"), Job::new()).is_err());
        let mut archive = open_zip(&output, &Job::new()).unwrap();
        assert_eq!(archive.len(), 1);
        let mut entry = archive.by_name("source.txt").unwrap();
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"hello archive");
        assert_eq!(fs::read(&input).unwrap(), contents);
    }

    #[test]
    fn zip_integrity_reports_corruption_without_writing_output() {
        use std::io::Write as _;
        use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("example.zip");
        let output = dir.path().join("test.json");
        let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let payload = b"this is the unique uncompressed fixture payload";
        zip.start_file(
            "data.txt",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(payload).unwrap();
        zip.start_file(
            "other.txt",
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
        zip.write_all(b"compressed file").unwrap();
        let mut bytes = zip.finish().unwrap().into_inner();
        fs::write(&input, &bytes).unwrap();
        let request = Request {
            operation: "zip-test".into(),
            input: input.clone(),
            output: output.clone(),
            ..Request::default()
        };
        handle(request.clone(), Job::new()).unwrap();
        let report: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(report["entries_checked"], 2);
        assert_eq!(
            report["uncompressed_bytes"],
            payload.len() + b"compressed file".len()
        );

        fs::remove_file(&output).unwrap();
        let offset = bytes
            .windows(payload.len())
            .position(|window| window == payload)
            .unwrap();
        bytes[offset] ^= 1;
        fs::write(input, bytes).unwrap();
        assert!(handle(request, Job::new())
            .unwrap_err()
            .message
            .contains("integrity"));
        assert!(!output.exists());
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
