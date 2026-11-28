#![forbid(unsafe_code)]
mod catalog;
pub mod catalogue_workspace;
mod encryption;
mod png_metadata;
use localwright_core::*;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
pub const OPERATIONS: &[Operation] = &[
    Operation {
        id: "inspect",
        label: "Inspect",
        hint: "Inspect signature, timestamps, hashes, a bounded hexadecimal sample, and supported format properties. Optional new JSON output.",
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
    Operation { id: "age-keygen", label: "Create age identity", hint: "Create a new X25519 identity file. Keep it private and backed up; only the public recipient key is shown." },
    Operation { id: "age-encrypt", label: "Encrypt with age", hint: "Enter an age X25519 recipient key and choose a new .age output. Streaming input limit: 4 GiB." },
    Operation { id: "age-decrypt", label: "Decrypt age file", hint: "Enter the path to a private age identity file and choose a new output. Authentication is checked before output is published." },
    Operation { id: "manifest-create", label: "Create checksum manifest", hint: "Create a versioned SHA-256 manifest for regular files below a directory. Choose a new .json output." },
    Operation { id: "manifest-verify", label: "Verify checksum manifest", hint: "Input a manifest JSON and enter its directory root as the parameter. Reports missing, changed and matching files without writing to them." },
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
    Operation { id: "zip-create-directory", label: "Create ZIP from directory", hint: "Compress regular files in a directory recursively into a new .zip archive. Symbolic links are skipped; empty directories and filesystem metadata are not stored." },
    Operation { id: "zip-extract-all", label: "Extract ZIP archive", hint: "Extract regular files and directories to a new destination folder. Traversal, links, collisions, and archives beyond the documented expansion limits are rejected." },
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
        id: "catalog-compare",
        label: "Compare saved inventories",
        hint: "Input the earlier JSON inventory or SQLite catalogue and enter the later inventory path. Optional new JSON report.",
    },
    Operation {
        id: "file-times",
        label: "Inspect file timestamps",
        hint: "Read available creation, modification and access times for a regular file. Optional JSON report.",
    },
    Operation {
        id: "catalog-search",
        label: "Search a saved file inventory",
        hint: "Input a saved JSON inventory or SQLite catalogue and enter a path fragment. Search works while the source drive is disconnected. Optional new JSON report.",
    },
    Operation { id: "catalog-refresh", label: "Refresh catalogue", hint: "Input a directory and enter an existing File Studio .sqlite catalogue path as Parameter. Appends a complete versioned scan and classifies additions, removals and changes only when the stable source identity matches; changed includes size or available modification-time differences. Unknown or changed identities are stored as a full-rescan baseline. Inaccessible paths produce a partial report and preserve the previous catalogue history." },
    Operation { id: "catalog-history", label: "View catalogue scan history", hint: "Input a File Studio .sqlite catalogue to list its latest 100 scan snapshots without accessing the original drive. Optional JSON report." },
    Operation { id: "catalog-compare-snapshots", label: "Compare catalogue snapshots", hint: "Input a saved File Studio .sqlite catalogue. Parameter JSON: {\"before_scan_id\":1,\"after_scan_id\":2}. Compares two retained snapshots without accessing the source volume." },
    Operation {
        id: "scan",
        label: "Scan",
        hint: "Read-only recursive directory inventory. Output JSON, CSV or .sqlite; if inaccessible paths make the scan partial, only a marked JSON report is saved. Partial scans are never used for catalogue refresh or removal counts. Symbolic links are skipped.",
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
fn modified_unix_ms(value: std::io::Result<std::time::SystemTime>) -> Option<i64> {
    use std::time::UNIX_EPOCH;
    let time = value.ok()?;
    let milliseconds = match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => i128::try_from(delta.as_millis()).ok()?,
        Err(error) => -i128::try_from(error.duration().as_nanos().div_ceil(1_000_000)).ok()?,
    };
    i64::try_from(milliseconds).ok()
}
fn file_times(path: &Path) -> Result<Value> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(Error::input("Choose a regular, non-symlink file"));
    }
    let timestamp = |value: std::io::Result<SystemTime>| {
        value.ok().and_then(|time| {
            let milliseconds = match time.duration_since(UNIX_EPOCH) {
                Ok(delta) => i128::try_from(delta.as_millis()).ok()?,
                Err(error) => {
                    -i128::try_from(error.duration().as_nanos().div_ceil(1_000_000)).ok()?
                }
            };
            i64::try_from(milliseconds).ok()
        })
    };
    Ok(json!({
        "schema_version": 1,
        "bytes": metadata.len(),
        "created_unix_ms": timestamp(metadata.created()),
        "modified_unix_ms": timestamp(metadata.modified()),
        "accessed_unix_ms": timestamp(metadata.accessed()),
    }))
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

/// Build the user-facing inspector report. The expensive hash pass remains a
/// separate primitive because catalogue and archive workflows reuse it.
fn inspect_report(path: &Path, job: &Job) -> Result<Value> {
    let mut report = inspect(path, job, None)?;
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Error::input("Expected regular non-symlink file"));
    }

    let mut file = fs::File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != report["bytes"].as_u64().unwrap_or(u64::MAX) {
        return Err(Error::input("File changed during inspection"));
    }
    let sample_len = usize::try_from(opened.len().min(64)).unwrap_or(64);
    let mut sample = vec![0; sample_len];
    file.read_exact(&mut sample)?;
    job.check()?;
    let after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if after.len() != opened.len()
        || after.modified()? != opened.modified()?
        || path_after.len() != opened.len()
        || path_after.modified()? != opened.modified()?
    {
        return Err(Error::input("File changed during inspection"));
    }

    let hex = sample
        .chunks(16)
        .map(|row| {
            row.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>();
    let ascii = sample
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect::<String>();
    let times = file_times(path)?;
    report["timestamps"] = times;
    report["hex_sample"] = json!({
        "offset": 0,
        "bytes_displayed": sample.len(),
        "hex_rows": hex,
        "ascii": ascii,
    });

    if report["signature"] == "image/png" {
        let metadata = if opened.len() <= 32 * 1024 * 1024 {
            png_metadata::process(path, None, job)
        } else {
            Err(Error::input(
                "PNG exceeds the 32 MiB metadata-inspection limit",
            ))
        };
        report["format_properties"] = match metadata {
            Ok(properties) => properties,
            Err(error) => json!({"inspection_error": error.message}),
        };
    } else {
        report["format_properties"] = Value::Null;
    }
    Ok(report)
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

fn archive_name(name: &str, is_dir: bool) -> Result<std::path::PathBuf> {
    let body = if is_dir {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    };
    if body.is_empty() || body.contains(['\\', ':', '\0']) || body.starts_with('/') {
        return Err(Error::input("ZIP contains an unsafe path"));
    }
    let components = body.split('/').collect::<Vec<_>>();
    if components.iter().any(|part| !safe_archive_component(part)) {
        return Err(Error::input("ZIP contains an unsafe path"));
    }
    Ok(components.iter().collect())
}

fn safe_archive_component(part: &str) -> bool {
    if part.is_empty()
        || matches!(part, "." | "..")
        || part.ends_with(['.', ' '])
        || part
            .chars()
            .any(|c| c.is_control() || "<>\"|?*".contains(c))
    {
        return false;
    }
    let stem = part
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
}

fn portable_relative(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| Error::input("Archive path is not Unicode"))?;
                if !safe_archive_component(part) || part.contains(['/', '\\', ':', '\0']) {
                    return Err(Error::input("Directory contains an unsafe archive path"));
                }
                parts.push(part);
            }
            _ => return Err(Error::input("Directory contains an unsafe archive path")),
        }
    }
    if parts.is_empty() {
        return Err(Error::input("Archive path is empty"));
    }
    Ok(parts.join("/"))
}

fn zip_extract_all(input: &Path, output: &Path, job: &Job) -> Result<Value> {
    const MAX_TOTAL: u64 = 128 * 1024 * 1024;
    const MAX_ENTRY: u64 = 32 * 1024 * 1024;
    let mut archive = open_zip(input, job)?;
    let mut plan = Vec::with_capacity(archive.len());
    let mut names = std::collections::HashSet::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        job.check()?;
        let member = archive
            .by_index_raw(index)
            .map_err(|e| Error::input(e.to_string()))?;
        let name = member.name().map_err(|e| Error::input(e.to_string()))?;
        let is_dir = member.is_dir();
        if member.is_symlink()
            || member.encrypted()
            || member
                .unix_mode()
                .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000 | 0o040000))
        {
            return Err(Error::input(
                "ZIP contains a link, encrypted entry, or special file",
            ));
        }
        let relative = archive_name(&name, is_dir)?;
        let normalized = relative.to_string_lossy().replace('\\', "/");
        if !names.insert(normalized.clone()) {
            return Err(Error::input("ZIP contains duplicate paths"));
        }
        if !is_dir {
            if member.size() > MAX_ENTRY || member.size() > MAX_TOTAL - total {
                return Err(Error::new(ErrorKind::Limit, "ZIP expansion limit exceeded"));
            }
            total += member.size();
        }
        plan.push((index, relative, is_dir, member.size()));
    }
    for (_, path, is_dir, _) in &plan {
        if !is_dir
            && plan
                .iter()
                .any(|(_, other, _, _)| other.starts_with(path) && other != path)
        {
            return Err(Error::input("ZIP file path conflicts with a nested entry"));
        }
    }
    if output.exists() || output.file_name().is_none() {
        return Err(Error::input("Choose a new destination directory"));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let final_path = parent.join(output.file_name().expect("checked filename"));
    if final_path.exists() {
        return Err(Error::input("Destination already exists"));
    }
    fs::create_dir(&final_path)?;
    let result = (|| -> Result<()> {
        let mut archive = open_zip(input, job)?;
        for (index, relative, is_dir, size) in &plan {
            job.check()?;
            let target = final_path.join(relative);
            if *is_dir {
                fs::create_dir_all(&target)?;
                continue;
            }
            let parent = target
                .parent()
                .ok_or_else(|| Error::input("Invalid ZIP output path"))?;
            fs::create_dir_all(parent)?;
            let mut member = archive
                .by_index(*index)
                .map_err(|e| Error::input(e.to_string()))?;
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            stream_zip_entry(&mut member, *size, file, index + 1, job)?;
        }
        job.check()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&final_path);
    }
    result?;
    Ok(
        json!({"schema_version":1,"files":plan.iter().filter(|(_,_,directory,_)| !directory).count(),"uncompressed_bytes":total,"destination":final_path}),
    )
}

fn zip_create_directory(input: &Path, output: &Path, job: &Job) -> Result<Value> {
    const MAX_TOTAL: u64 = 128 * 1024 * 1024;
    const MAX_FILE: u64 = 32 * 1024 * 1024;
    if !output
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
    {
        return Err(Error::input("Choose .zip output"));
    }
    let metadata = fs::symlink_metadata(input)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::input("Choose a non-symlink directory"));
    }
    let root = fs::canonicalize(input)?;
    let rows = scan(&root, job)?.into_complete_files()?;
    if rows.len() > 4096 {
        return Err(Error::new(
            ErrorKind::Limit,
            "ZIP file count limit exceeded",
        ));
    }
    let mut total = 0u64;
    for row in &rows {
        let bytes = row["bytes"].as_u64().unwrap_or(u64::MAX);
        if bytes > MAX_FILE || bytes > MAX_TOTAL - total {
            return Err(Error::new(
                ErrorKind::Limit,
                "ZIP input size limit exceeded",
            ));
        }
        total += bytes;
        portable_relative(Path::new(row["path"].as_str().unwrap_or_default()))?;
    }
    write_new(output, |file| {
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let mut buffer = [0u8; 32 * 1024];
        for row in &rows {
            job.check()?;
            let relative = row["path"].as_str().expect("scan reports a path");
            let path = root.join(relative);
            if !fs::canonicalize(&path)?.starts_with(&root) {
                return Err(Error::input(
                    "File escaped the archive root during creation",
                ));
            }
            let before = fs::symlink_metadata(&path)?;
            if !before.is_file()
                || before.file_type().is_symlink()
                || before.len() != row["bytes"].as_u64().unwrap_or_default()
            {
                return Err(Error::input("Directory changed during ZIP creation"));
            }
            let mut source = fs::File::open(&path)?;
            writer
                .start_file(portable_relative(Path::new(relative))?, options)
                .map_err(|e| Error::input(e.to_string()))?;
            let mut read = 0u64;
            loop {
                job.check()?;
                let n = source.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                read += n as u64;
                if read > before.len() {
                    return Err(Error::input("Source grew during ZIP creation"));
                }
                writer.write_all(&buffer[..n])?;
            }
            let after = source.metadata()?;
            if read != before.len()
                || after.len() != before.len()
                || before.modified()? != after.modified()?
            {
                return Err(Error::input("Source changed during ZIP creation"));
            }
        }
        job.check()?;
        writer.finish().map_err(|e| Error::input(e.to_string()))?;
        Ok(())
    })?;
    Ok(json!({"schema_version":1,"files":rows.len(),"uncompressed_bytes":total}))
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

struct ScanReport {
    files: Vec<Value>,
    warnings: Vec<String>,
    omitted_warnings: usize,
    complete: bool,
}

impl ScanReport {
    fn mark_incomplete(&mut self, root: &Path, path: Option<&Path>, error: impl std::fmt::Display) {
        self.complete = false;
        let display_path = path
            .and_then(|path| path.strip_prefix(root).ok())
            .and_then(Path::to_str)
            .filter(|path| !path.is_empty())
            .unwrap_or("<directory entry>");
        if self.warnings.len() < 128 {
            self.warnings.push(format!("{display_path}: {error}"));
        } else {
            self.omitted_warnings += 1;
        }
    }

    fn into_complete_files(self) -> Result<Vec<Value>> {
        if !self.complete {
            return Err(Error::input(format!(
                "Directory scan was incomplete; {} file entries were found and the incomplete inventory was not used. First issue: {}",
                self.files.len(),
                self.warnings.first().map(String::as_str).unwrap_or("unknown traversal error")
            )));
        }
        Ok(self.files)
    }

    fn report_value(&self) -> Value {
        if self.complete {
            json!({"schema_version":1,"files":self.files})
        } else {
            json!({"schema_version":2,"complete":false,"files":self.files,"warnings":self.warnings,"omitted_warnings":self.omitted_warnings})
        }
    }
}

fn scan(root: &Path, j: &Job) -> Result<ScanReport> {
    // The number of files is unknown until traversal completes, so expose this phase
    // as indeterminate rather than treating the safety limit as a completion estimate.
    j.progress(0, 0);
    let m = fs::symlink_metadata(root)?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(Error::input("Choose a non-symlink directory"));
    }
    let mut stack = vec![(root.to_path_buf(), 0)];
    let mut report = ScanReport {
        files: vec![],
        warnings: vec![],
        omitted_warnings: 0,
        complete: true,
    };
    let mut count = 0usize;
    'walk: while let Some((dir, depth)) = stack.pop() {
        j.check()?;
        if depth > 64 {
            report.mark_incomplete(root, Some(&dir), "maximum directory depth of 64 exceeded");
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                report.mark_incomplete(root, Some(&dir), error);
                continue;
            }
        };
        for entry in entries {
            j.check()?;
            let e = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    report.mark_incomplete(root, Some(&dir), error);
                    continue;
                }
            };
            let p = e.path();
            let m = match fs::symlink_metadata(&p) {
                Ok(metadata) => metadata,
                Err(error) => {
                    report.mark_incomplete(root, Some(&p), error);
                    continue;
                }
            };
            count += 1;
            if count > 10000 {
                report.mark_incomplete(root, Some(&dir), "scan stopped at the 10,000-entry limit");
                break 'walk;
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
                if let Some(relative) = relative.to_str() {
                    report.files.push(json!({"path":relative,"bytes":m.len(),"modified_unix_ms":modified_unix_ms(m.modified())}));
                } else {
                    report.mark_incomplete(
                        root,
                        Some(&p),
                        "path is not valid Unicode and cannot be represented",
                    );
                }
            }
        }
    }
    report
        .files
        .sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(report)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    algorithm: String,
    files: Vec<ManifestFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    path: String,
    bytes: u64,
    sha256: String,
}

fn manifest_create(root: &Path, job: &Job) -> Result<Value> {
    let rows = scan(root, job)?.into_complete_files()?;
    let mut total = 0u64;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        job.check()?;
        let relative = row["path"].as_str().expect("scan reports a path");
        let relative = portable_relative(Path::new(relative))?;
        let bytes = row["bytes"].as_u64().expect("scan reports a size");
        total = total
            .checked_add(bytes)
            .filter(|&n| n <= 1024 * 1024 * 1024)
            .ok_or_else(|| Error::new(ErrorKind::Limit, "Manifest hashing exceeds 1 GiB"))?;
        let path = root.join(&relative);
        if !fs::canonicalize(&path)?.starts_with(root) {
            return Err(Error::input(
                "File escaped the manifest root during scanning",
            ));
        }
        let detail = inspect(&path, job, Some(bytes))?;
        files.push(json!({"path":relative,"bytes":bytes,"sha256":detail["sha256"]}));
    }
    Ok(json!({"schema_version":1,"algorithm":"sha256","files":files}))
}

fn manifest_verify(manifest_path: &Path, root: &Path, job: &Job) -> Result<Value> {
    if manifest_path == root || manifest_path.starts_with(root) {
        return Err(Error::input(
            "Keep the manifest outside the scanned directory",
        ));
    }
    let manifest_meta = fs::symlink_metadata(manifest_path)?;
    if !manifest_meta.is_file() || manifest_meta.file_type().is_symlink() {
        return Err(Error::input("Manifest must be a regular non-symlink file"));
    }
    let manifest: Manifest =
        serde_json::from_slice(&read_bounded(manifest_path, 8 * 1024 * 1024)?)?;
    if manifest.schema_version != 1
        || manifest.algorithm != "sha256"
        || manifest.files.len() > 10_000
    {
        return Err(Error::input("Unsupported or oversized checksum manifest"));
    }
    let root_meta = fs::symlink_metadata(root)?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
        return Err(Error::input("Choose a non-symlink directory root"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut total = 0u64;
    let mut matches = Vec::new();
    let mut changed = Vec::new();
    let mut missing = Vec::new();
    for entry in &manifest.files {
        job.check()?;
        let relative = Path::new(&entry.path);
        if entry.path.is_empty()
            || relative.is_absolute()
            || !seen.insert(entry.path.as_str())
            || relative.components().any(|part| match part {
                std::path::Component::Normal(name) => name
                    .to_str()
                    .is_none_or(|name| !safe_archive_component(name)),
                _ => true,
            })
            || entry.sha256.len() != 64
            || !entry.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::input("Manifest contains an unsafe or invalid entry"));
        }
        total = total
            .checked_add(entry.bytes)
            .filter(|&n| n <= 1024 * 1024 * 1024)
            .ok_or_else(|| Error::new(ErrorKind::Limit, "Manifest verification exceeds 1 GiB"))?;
        let mut path = root.to_path_buf();
        let mut unavailable = false;
        let mut unsafe_path = false;
        let components = relative.components().collect::<Vec<_>>();
        for (index, component) in components.iter().enumerate() {
            path.push(component.as_os_str());
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    unavailable = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            if meta.file_type().is_symlink()
                || (index + 1 < components.len() && !meta.is_dir())
                || (index + 1 == components.len() && !meta.is_file())
            {
                unsafe_path = true;
                break;
            }
        }
        if unavailable {
            missing.push(entry.path.clone());
            continue;
        }
        if unsafe_path {
            changed.push(entry.path.clone());
            continue;
        }
        if fs::metadata(&path)?.len() != entry.bytes {
            changed.push(entry.path.clone());
            continue;
        }
        let actual = inspect(&path, job, Some(entry.bytes))?;
        if actual["sha256"]
            .as_str()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(&entry.sha256))
        {
            matches.push(entry.path.clone());
        } else {
            changed.push(entry.path.clone());
        }
    }
    Ok(
        json!({"schema_version":1,"algorithm":"sha256","verified":matches.len(),"matches":matches,"changed":changed,"missing":missing}),
    )
}
fn directory_usage(root: &Path, job: &Job) -> Result<Value> {
    let mut total = 0u64;
    let mut root_bytes = 0u64;
    let mut directories = std::collections::BTreeMap::<String, u64>::new();
    let files = scan(root, job)?.into_complete_files()?;
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
    let files = scan(root, job)?.into_complete_files()?;
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
    if r.operation == "age-keygen" {
        let report = encryption::generate_key(&r.output)?;
        return Ok(Outcome {
            preview: serde_json::to_string_pretty(&report)?,
            written: Some(r.output),
            warnings: vec!["The saved identity file contains a private key. Restrict access to it and keep a secure backup. The recipient key is public. No passphrase is applied to the identity file.".into()],
            ..Outcome::default()
        });
    }
    if r.operation == "age-encrypt" {
        let report = encryption::encrypt(&r.input, &r.output, &r.parameter, &j)?;
        return Ok(Outcome {
            preview: serde_json::to_string_pretty(&report)?,
            written: Some(r.output),
            warnings: vec!["Encryption uses the age X25519 format and authenticates ciphertext integrity. It does not identify the sender; share the recipient key through a trusted channel.".into()],
            ..Outcome::default()
        });
    }
    if r.operation == "age-decrypt" {
        if r.parameter.trim().is_empty() {
            return Err(Error::input(
                "Enter the private identity file path as the parameter",
            ));
        }
        let report = encryption::decrypt(&r.input, &r.output, Path::new(r.parameter.trim()), &j)?;
        return Ok(Outcome {
            preview: serde_json::to_string_pretty(&report)?,
            written: Some(r.output),
            warnings: vec!["Authenticated age plaintext was written to a new file. The identity file remains unchanged.".into()],
            ..Outcome::default()
        });
    }
    let value = match r.operation.as_str() {
        "inspect" => inspect_report(&r.input, &j)?,
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
        "manifest-create" => {
            if r.output.extension().and_then(|ext| ext.to_str()) != Some("json") {
                return Err(Error::input("Choose .json manifest output"));
            }
            let root_metadata = fs::symlink_metadata(&r.input)?;
            if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
                return Err(Error::input("Choose a non-symlink directory"));
            }
            let root = fs::canonicalize(&r.input)?;
            let parent = r
                .output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let canonical_parent = fs::canonicalize(parent)?;
            let output = canonical_parent.join(
                r.output
                    .file_name()
                    .ok_or_else(|| Error::input("Manifest output filename is required"))?,
            );
            if output.starts_with(&root) {
                return Err(Error::input(
                    "Save the manifest outside the scanned directory",
                ));
            }
            let manifest = manifest_create(&root, &j)?;
            let encoded = serde_json::to_vec_pretty(&manifest)?;
            j.check()?;
            write_bytes(&r.output, &encoded)?;
            return Ok(Outcome {
                preview: serde_json::to_string_pretty(&manifest)?,
                written: Some(r.output),
                warnings: vec!["The SHA-256 manifest records regular file paths relative to the selected root. It does not authenticate who created the manifest.".into()],
                ..Outcome::default()
            });
        }
        "manifest-verify" => {
            if r.parameter.trim().is_empty() {
                return Err(Error::input("Enter the directory root for this manifest"));
            }
            let manifest_metadata = fs::symlink_metadata(&r.input)?;
            if !manifest_metadata.is_file() || manifest_metadata.file_type().is_symlink() {
                return Err(Error::input("Manifest must be a regular non-symlink file"));
            }
            let root_metadata = fs::symlink_metadata(Path::new(&r.parameter))?;
            if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
                return Err(Error::input("Choose a non-symlink directory root"));
            }
            let root = fs::canonicalize(Path::new(&r.parameter))?;
            let manifest = fs::canonicalize(&r.input)?;
            manifest_verify(&manifest, &root, &j)?
        }
        "duplicates" => duplicate_candidates(&r.input, &j)?,
        "directory-usage" => directory_usage(&r.input, &j)?,
        "zip-create" | "zip-extract-entry" | "zip-create-directory" | "zip-extract-all" => {
            let (value, warning) = if r.operation == "zip-create" {
                (
                    create_zip(&r.input, &r.output, &r.parameter, &j)?,
                    "ZIP creation preserves file contents. The archive does not carry source ownership, original timestamps or extended attributes.",
                )
            } else if r.operation == "zip-create-directory" {
                (
                    zip_create_directory(&r.input, &r.output, &j)?,
                    "The ZIP contains regular file contents only. Symbolic links, empty directories, ownership, timestamps and extended attributes are not included.",
                )
            } else if r.operation == "zip-extract-all" {
                (
                    zip_extract_all(&r.input, &r.output, &j)?,
                    "Extracted untrusted file bytes to a new folder. Review files before opening them; the operation does not validate their format or safety.",
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
        "file-times" => file_times(&r.input)?,
        "catalog-compare" => catalog::compare(&r.input, Path::new(&r.parameter), &j)?,
        "catalog-search" => catalog::search(&r.input, &r.parameter, &j)?,
        "catalog-history" => catalog::history(&r.input, &j)?,
        "catalog-compare-snapshots" => catalog::compare_snapshots(&r.input, &r.parameter, &j)?,
        "catalog-refresh" => {
            let report = scan(&r.input, &j)?;
            if !report.complete {
                let warning = format!(
                    "Catalogue refresh was not saved because traversal was incomplete. {} issue(s) were recorded; no removed-file counts were inferred.",
                    report.warnings.len() + report.omitted_warnings
                );
                return Ok(Outcome {
                    preview: serde_json::to_string_pretty(&report.report_value())?,
                    warnings: vec![warning],
                    ..Outcome::default()
                });
            }
            let files = report.files;
            catalog::refresh(Path::new(&r.parameter), &r.input, &files, &j)?
        }
        "scan" => scan(&r.input, &j)?.report_value(),
        _ => return Err(Error::input("Unknown operation")),
    };
    let mut written = None;
    let mut encoded = serde_json::to_string_pretty(&value)?;
    let incomplete_scan = r.operation == "scan" && value["complete"] == false;
    if incomplete_scan
        && !r.output.as_os_str().is_empty()
        && !r
            .output
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        return Ok(Outcome {
            preview: encoded,
            warnings: vec![
                "The scan is incomplete. It was not saved as CSV or SQLite because those formats cannot carry the required completeness marker. Save the marked JSON report to retain the partial results.".into(),
            ],
            ..Outcome::default()
        });
    }
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
            Some(extension)
                if r.operation == "scan"
                    && (extension.eq_ignore_ascii_case("sqlite")
                        || extension.eq_ignore_ascii_case("sqlite3")) =>
            {
                if incomplete_scan {
                    return Err(Error::input(
                        "An incomplete scan cannot be saved as a SQLite catalogue",
                    ));
                }
                let files = value["files"]
                    .as_array()
                    .ok_or_else(|| Error::input("Scan report has no file list"))?;
                let report = catalog::create(&r.input, files, &r.output, &j)?;
                encoded = serde_json::to_string_pretty(&report)?;
            }
            _ if r.operation == "scan" => {
                return Err(Error::input("Choose .json, .csv or .sqlite output"))
            }
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
        warnings: vec![if incomplete_scan {
            "This is a partial scan (schema version 2). It contains inaccessible or skipped paths and must not be used to infer removed files. SQLite refresh was not attempted; JSON inventory loaders reject incomplete reports.".into()
        } else if r.operation == "verify" {
            "A match verifies integrity against the supplied checksum. Use a trusted source for the checksum.".into()
        } else if r.operation == "inspect" {
            "The hexadecimal sample contains original file bytes and may be sensitive. Signature identification is limited; PNG chunk inspection does not decode metadata values.".into()
        } else if r.operation == "duplicates" {
            "Candidates share a size and BLAKE3 checksum. Review files before making any changes."
                .into()
        } else if r.operation == "directory-usage" {
            "Logical file sizes only. Hard links are counted per path, and symlinks are skipped."
                .into()
        } else if r.operation == "catalog-compare" {
            "Inventory comparison uses saved paths and sizes. Same-size files may have different contents.".into()
        } else if r.operation == "file-times" {
            "Timestamps are milliseconds since the Unix epoch. Unavailable timestamps appear as null.".into()
        } else if r.operation == "catalog-search" {
            "Results describe the saved scan. Files may have moved or changed. The source drive is not accessed.".into()
        } else if r.operation == "catalog-refresh" {
            "A new scan snapshot was appended in one SQLite transaction. Older history remains available; the source scan is read-only.".into()
        } else if r.operation == "catalog-history" {
            "History comes from the local catalogue only. Original volumes and listed paths are not opened.".into()
        } else if r.operation == "catalog-compare-snapshots" {
            "Comparison uses saved relative paths and file sizes only. Source identity is reported; same-size content changes cannot be detected. The original volume is not accessed.".into()
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

/// Handle File Studio routes that require a native path value outside the text-only
/// operation contract. The catalogue UI keeps selected paths intact and resolves
/// saved relative paths beneath the user-selected source folder before inspection.
pub fn handle_workspace(r: Request, j: Job) -> Result<Outcome> {
    if r.operation == "workspace-catalog-inspect" {
        let path = resolve_catalogue_selection(&r.input, &r.parameter)?;
        let report = inspect_report(&path, &j)?;
        return Ok(Outcome {
            preview: serde_json::to_string_pretty(&report)?,
            warnings: vec![
                "Read-only inspection. The bounded hexadecimal sample contains original file bytes and may be sensitive.".into(),
            ],
            ..Outcome::default()
        });
    }
    if r.operation != "workspace-catalog-refresh" {
        return handle(r, j);
    }
    if r.output.as_os_str().is_empty() {
        return Err(Error::input("Choose an existing SQLite catalogue"));
    }
    let files = scan(&r.input, &j)?;
    if !files.complete {
        let warning = format!(
            "Catalogue refresh was not saved because traversal was incomplete. {} issue(s) were recorded; no removed-file counts were inferred.",
            files.warnings.len() + files.omitted_warnings
        );
        return Ok(Outcome {
            preview: serde_json::to_string_pretty(&files.report_value())?,
            warnings: vec![warning],
            ..Outcome::default()
        });
    }
    let report = catalog::refresh(&r.output, &r.input, &files.files, &j)?;
    Ok(Outcome {
        preview: serde_json::to_string_pretty(&report)?,
        written: Some(r.output),
        warnings: vec![
            "A complete read-only scan was appended to the existing catalogue. Earlier history remains available. Change counts use file size and available modification times only when stable source identity matches; content changes preserving both attributes may be missed. Otherwise no cross-source comparison is claimed.".into(),
        ],
        ..Outcome::default()
    })
}

fn resolve_catalogue_selection(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty() || relative.len() > 64 * 1024 {
        return Err(Error::input("Choose a valid catalogue file path"));
    }
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(Error::input("Choose a non-symlink source folder"));
    }
    let root = fs::canonicalize(root)?;
    let relative = Path::new(relative);
    if relative.is_absolute() {
        return Err(Error::input("Catalogue paths must be relative"));
    }
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Error::input("Catalogue path contains an unsafe component"));
    }

    let mut candidate = root.clone();
    for (index, component) in components.iter().enumerate() {
        candidate.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&candidate)?;
        if metadata.file_type().is_symlink()
            || (index + 1 < components.len() && !metadata.is_dir())
            || (index + 1 == components.len() && !metadata.is_file())
        {
            return Err(Error::input(
                "Catalogue selection must contain only directories and a regular file",
            ));
        }
    }

    let canonical = fs::canonicalize(&candidate)?;
    if !canonical.starts_with(&root) || !fs::metadata(&canonical)?.is_file() {
        return Err(Error::input("Selected file escaped the source folder"));
    }
    Ok(canonical)
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
        assert_eq!(scan(d.path(), &Job::new()).unwrap().files.len(), 1);
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

    #[cfg(unix)]
    #[test]
    fn inaccessible_subtree_is_reported_and_never_becomes_a_removal_snapshot() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("volume");
        let denied = root.join("private");
        let database = directory.path().join("volume.sqlite");
        let partial_inventory = directory.path().join("partial.json");
        fs::create_dir_all(&denied).unwrap();
        fs::write(root.join("visible.txt"), b"visible").unwrap();
        fs::write(denied.join("secret.txt"), b"secret").unwrap();

        let baseline = scan(&root, &Job::new()).unwrap();
        assert!(baseline.complete);
        catalog::create(&root, &baseline.files, &database, &Job::new()).unwrap();

        fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(&denied).is_ok() {
            // Root can bypass mode-bit restrictions; retain the test on ordinary CI
            // users, where this represents an inaccessible child directory.
            fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        let outcome = handle_workspace(
            Request {
                operation: "workspace-catalog-refresh".into(),
                input: root.clone(),
                output: database.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let partial: Value = serde_json::from_str(&outcome.preview).unwrap();
        assert_eq!(partial["schema_version"], 2);
        assert_eq!(partial["complete"], false);
        assert_eq!(partial["files"].as_array().unwrap().len(), 1);
        assert!(partial["warnings"][0].as_str().unwrap().contains("private"));
        assert!(outcome.written.is_none());
        assert!(outcome.warnings[0].contains("not saved"));

        let history = catalog::history(&database, &Job::new()).unwrap();
        assert_eq!(history["scans"].as_array().unwrap().len(), 1);
        fs::write(&partial_inventory, &outcome.preview).unwrap();
        assert!(catalog::search(&partial_inventory, "visible", &Job::new()).is_err());

        fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn integrated_inspection_combines_integrity_timestamps_hex_and_png_properties() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sample.png");
        let output = directory.path().join("inspection.json");
        let fixture = include_bytes!("../tests/fixtures/png-metadata.png");
        fs::write(&path, fixture).unwrap();

        let outcome = handle(
            Request {
                operation: "inspect".into(),
                input: path.clone(),
                output: output.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(outcome.written, Some(output.clone()));
        let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(report["signature"], "image/png");
        assert_eq!(report["bytes"], fixture.len());
        assert!(report["timestamps"]["modified_unix_ms"].is_number());
        assert_eq!(report["hex_sample"]["offset"], 0);
        assert_eq!(report["hex_sample"]["bytes_displayed"], 64);
        assert_eq!(
            report["hex_sample"]["hex_rows"][0],
            "89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52"
        );
        assert_eq!(report["format_properties"]["removable"], 4);
        assert_eq!(fs::read(path).unwrap(), fixture);
    }

    #[test]
    fn integrated_inspection_handles_short_binary_files_without_expansion() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sample.bin");
        fs::write(&path, [0, b'A', 0x80]).unwrap();

        let report = inspect_report(&path, &Job::new()).unwrap();
        assert_eq!(report["signature"], "unknown");
        assert_eq!(report["hex_sample"]["hex_rows"][0], "00 41 80");
        assert_eq!(report["hex_sample"]["ascii"], ".A.");
        assert!(report["timestamps"].is_object());
        assert!(report["format_properties"].is_null());
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
    fn searches_saved_inventory_after_source_files_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("volume");
        let inventory = dir.path().join("inventory.json");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("Café Notes.txt"), b"abc").unwrap();
        fs::write(source.join("Other.txt"), b"abcdef").unwrap();
        handle(
            Request {
                operation: "scan".into(),
                input: source.clone(),
                output: inventory.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        fs::remove_file(source.join("Café Notes.txt")).unwrap();
        fs::remove_file(source.join("Other.txt")).unwrap();
        fs::remove_dir(source).unwrap();
        let result = handle(
            Request {
                operation: "catalog-search".into(),
                input: inventory,
                parameter: "CAFÉ".into(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let report: Value = serde_json::from_str(&result.preview).unwrap();
        assert_eq!(report["catalogued_files"], 2);
        assert_eq!(report["matched_files"], 1);
        assert_eq!(
            report["files"][0],
            json!({"path":"Café Notes.txt","bytes":3})
        );
    }

    #[test]
    fn sqlite_catalog_searches_offline_and_retains_append_only_scan_history() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("removable-volume");
        let database = directory.path().join("volume.sqlite");
        let earlier = directory.path().join("earlier.json");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("report.txt"), b"first").unwrap();

        handle(
            Request {
                operation: "scan".into(),
                input: root.clone(),
                output: database.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert!(handle(
            Request {
                operation: "scan".into(),
                input: root.clone(),
                output: database.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .is_err());

        handle(
            Request {
                operation: "scan".into(),
                input: root.clone(),
                output: earlier.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        fs::write(root.join("report.txt"), b"changed-size").unwrap();
        fs::write(root.join("notes.txt"), b"new").unwrap();
        let refreshed = handle(
            Request {
                operation: "catalog-refresh".into(),
                input: root.clone(),
                parameter: database.to_string_lossy().into_owned(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let refresh_report: Value = serde_json::from_str(&refreshed.preview).unwrap();
        assert_eq!(refresh_report["history"], true);
        if catalog::stable_source_identity(&root).is_some() {
            assert_eq!(refresh_report["comparison_mode"], "same-source");
            assert_eq!(refresh_report["added"], 1);
            assert_eq!(refresh_report["changed"], 1);
            assert_eq!(refresh_report["removed"], 0);
        } else {
            assert_eq!(refresh_report["comparison_mode"], "full-rescan");
        }
        let compared = handle(
            Request {
                operation: "catalog-compare".into(),
                input: earlier.clone(),
                parameter: database.to_string_lossy().into_owned(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let comparison: Value = serde_json::from_str(&compared.preview).unwrap();
        assert_eq!(comparison["added"][0]["path"], "notes.txt");
        assert_eq!(comparison["size_changed"][0]["path"], "report.txt");

        fs::remove_file(root.join("report.txt")).unwrap();
        fs::remove_file(root.join("notes.txt")).unwrap();
        fs::remove_dir(root).unwrap();
        let searched = handle(
            Request {
                operation: "catalog-search".into(),
                input: database.clone(),
                parameter: "NOTES".into(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let results: Value = serde_json::from_str(&searched.preview).unwrap();
        assert_eq!(results["catalogued_files"], 2);
        assert_eq!(results["matched_files"], 1);
        assert_eq!(results["files"][0]["path"], "notes.txt");

        let history = handle(
            Request {
                operation: "catalog-history".into(),
                input: database,
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let scans: Value = serde_json::from_str(&history.preview).unwrap();
        assert_eq!(scans["scans"].as_array().unwrap().len(), 2);
        assert_eq!(scans["scans"][0]["files"], 2);
    }

    #[test]
    fn selected_catalogue_file_inspection_is_read_only_and_rejects_escape_paths() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source");
        let outside = directory.path().join("outside.txt");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/report.txt"), b"inspect this file").unwrap();
        fs::write(&outside, b"outside the source").unwrap();

        let rows = scan(&root, &Job::new()).unwrap().files;
        let saved_relative_path = rows[0]["path"].as_str().unwrap().to_owned();
        let inspected = handle_workspace(
            Request {
                operation: "workspace-catalog-inspect".into(),
                input: root.clone(),
                parameter: saved_relative_path.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let report: Value = serde_json::from_str(&inspected.preview).unwrap();
        assert_eq!(report["bytes"], b"inspect this file".len() as u64);
        assert!(report["sha256"].as_str().is_some());
        assert!(inspected.written.is_none());
        assert_eq!(
            fs::read(root.join(saved_relative_path)).unwrap(),
            b"inspect this file"
        );
        assert_eq!(fs::read(outside).unwrap(), b"outside the source");

        for unsafe_path in ["../outside.txt", "nested/../nested/report.txt", ""] {
            assert!(handle_workspace(
                Request {
                    operation: "workspace-catalog-inspect".into(),
                    input: root.clone(),
                    parameter: unsafe_path.into(),
                    ..Request::default()
                },
                Job::new(),
            )
            .is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn selected_catalogue_file_inspection_rejects_symlink_components() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source");
        let outside = directory.path().join("outside.txt");
        fs::create_dir(&root).unwrap();
        fs::write(&outside, b"private outside content").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("linked.txt")).unwrap();

        let result = handle_workspace(
            Request {
                operation: "workspace-catalog-inspect".into(),
                input: root,
                parameter: "linked.txt".into(),
                ..Request::default()
            },
            Job::new(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn sqlite_catalog_rejects_wrong_schema_and_catalogue_inside_scanned_tree() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("root");
        let wrong_schema = directory.path().join("wrong.sqlite");
        let wrong_page_size = directory.path().join("large-pages.sqlite");
        fs::create_dir(&root).unwrap();
        let db = rusqlite::Connection::open(&wrong_schema).unwrap();
        db.execute_batch("PRAGMA application_id=123; PRAGMA user_version=1;")
            .unwrap();
        drop(db);
        assert!(catalog::history(&wrong_schema, &Job::new()).is_err());
        let db = rusqlite::Connection::open(&wrong_page_size).unwrap();
        db.execute_batch(
            "PRAGMA page_size=8192; PRAGMA application_id=1280791107; PRAGMA user_version=1;",
        )
        .unwrap();
        drop(db);
        assert!(catalog::history(&wrong_page_size, &Job::new()).is_err());
        let inside = root.join("catalog.sqlite");
        let rows = scan(&root, &Job::new()).unwrap().files;
        assert!(catalog::create(&root, &rows, &inside, &Job::new()).is_err());
        assert!(!inside.exists());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn native_catalogue_refresh_keeps_non_unicode_selected_paths() {
        use std::os::unix::ffi::OsStringExt;

        let directory = tempfile::tempdir().unwrap();
        let root = directory
            .path()
            .join(std::ffi::OsString::from_vec(b"source-\xff".to_vec()));
        let database = directory.path().join(std::ffi::OsString::from_vec(
            b"catalogue-\xff.sqlite".to_vec(),
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file.txt"), b"original").unwrap();

        handle(
            Request {
                operation: "scan".into(),
                input: root.clone(),
                output: database.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let refreshed = handle_workspace(
            Request {
                operation: "workspace-catalog-refresh".into(),
                input: root,
                output: database.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&refreshed.preview).unwrap()["scan_id"],
            2
        );
        let history = handle(
            Request {
                operation: "catalog-history".into(),
                input: database,
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&history.preview).unwrap()["scans"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
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
