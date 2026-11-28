//! Versioned, bounded backups of a user-selected directory tree. The archive
//! carries hashes for integrity checking but is not signed or authenticated.

use localwright_core::{read_bounded, write_new, Error, ErrorKind, Job, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

const FORMAT: &str = "file-studio-backup";
const VERSION: u32 = 1;
const MANIFEST_NAME: &str = "_file_studio_backup/manifest.json";
const PAYLOAD_PREFIX: &str = "payload/";
const MAX_ARCHIVE: u64 = 160 * 1024 * 1024;
const MAX_FILE: u64 = 32 * 1024 * 1024;
const MAX_TOTAL: u64 = 128 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 64;
const MAX_PATH: usize = 1024;
const MAX_MANIFEST: u64 = 4 * 1024 * 1024;
const BUFFER: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    format: String,
    schema_version: u32,
    entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    path: String,
    kind: EntryKind,
    bytes: u64,
    sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceEntry {
    path: String,
    kind: EntryKind,
    bytes: u64,
    modified: Option<SystemTime>,
}

#[derive(Debug, Clone)]
struct RestoreEntry {
    index: usize,
    path: PathBuf,
    kind: EntryKind,
    bytes: u64,
    sha256: Option<String>,
}

struct RestorePlan {
    entries: Vec<RestoreEntry>,
    total_bytes: u64,
    files: usize,
    directories: usize,
}

pub fn create(input: &Path, output: &Path, job: &Job) -> Result<Value> {
    if !output
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("fsbackup"))
    {
        return Err(Error::input("Choose .fsbackup output"));
    }
    let before_root = fs::symlink_metadata(input)?;
    if !before_root.is_dir() || before_root.file_type().is_symlink() {
        return Err(Error::input("Choose a non-symlink directory to back up"));
    }
    let root = fs::canonicalize(input)?;
    let output_parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let canonical_parent = fs::canonicalize(output_parent)?;
    let output_path = canonical_parent.join(
        output
            .file_name()
            .ok_or_else(|| Error::input("Choose a backup filename"))?,
    );
    if output_path.starts_with(&root) {
        return Err(Error::input("Save the backup outside the source directory"));
    }

    let source_entries = collect_tree(&root, job)?;
    check_case_collisions(source_entries.iter().map(|entry| entry.path.as_str()))?;
    let total_bytes = source_entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
        .try_fold(0u64, |total, entry| total.checked_add(entry.bytes))
        .filter(|total| *total <= MAX_TOTAL)
        .ok_or_else(|| Error::new(ErrorKind::Limit, "Backup exceeds the 128 MiB data limit"))?;
    let mut manifest_entries = Vec::with_capacity(source_entries.len());
    let mut completed = 0u64;
    job.progress(0, total_bytes);

    write_new(output, |file| {
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let mut buffer = [0u8; BUFFER];
        for entry in &source_entries {
            job.check()?;
            let archive_name = format!("{PAYLOAD_PREFIX}{}", entry.path);
            if entry.kind == EntryKind::Directory {
                writer
                    .add_directory(format!("{archive_name}/"), options)
                    .map_err(|error| Error::input(format!("Cannot write backup: {error}")))?;
                manifest_entries.push(ManifestEntry {
                    path: entry.path.clone(),
                    kind: EntryKind::Directory,
                    bytes: 0,
                    sha256: None,
                });
                continue;
            }

            let path = root.join(&entry.path);
            let path_metadata = fs::symlink_metadata(&path)?;
            if !path_metadata.is_file()
                || path_metadata.file_type().is_symlink()
                || path_metadata.len() != entry.bytes
                || path_metadata.modified().ok() != entry.modified
                || !fs::canonicalize(&path)?.starts_with(&root)
            {
                return Err(Error::input("Source tree changed before backup"));
            }
            let mut source = File::open(&path)?;
            let opened = source.metadata()?;
            if !opened.is_file()
                || opened.len() != entry.bytes
                || opened.modified().ok() != entry.modified
                || !same_file_identity(&path, &source)?
            {
                return Err(Error::input("Source file changed before backup"));
            }
            writer
                .start_file(&archive_name, options)
                .map_err(|error| Error::input(format!("Cannot write backup: {error}")))?;
            let mut hasher = Sha256::new();
            let mut copied = 0u64;
            loop {
                job.check()?;
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                copied = copied
                    .checked_add(count as u64)
                    .filter(|size| *size <= entry.bytes && *size <= MAX_FILE)
                    .ok_or_else(|| Error::input("Source file grew during backup"))?;
                hasher.update(&buffer[..count]);
                writer.write_all(&buffer[..count])?;
                job.progress(completed.saturating_add(copied), total_bytes);
            }
            let after = source.metadata()?;
            let path_after = fs::symlink_metadata(&path)?;
            if copied != entry.bytes
                || after.len() != entry.bytes
                || after.modified().ok() != entry.modified
                || !path_after.is_file()
                || path_after.file_type().is_symlink()
                || path_after.len() != entry.bytes
                || path_after.modified().ok() != entry.modified
                || !same_file_identity(&path, &source)?
            {
                return Err(Error::input("Source file changed during backup"));
            }
            completed = completed.saturating_add(copied);
            manifest_entries.push(ManifestEntry {
                path: entry.path.clone(),
                kind: EntryKind::File,
                bytes: copied,
                sha256: Some(format!("{:x}", hasher.finalize())),
            });
            job.progress(completed, total_bytes);
        }

        let manifest = BackupManifest {
            format: FORMAT.to_string(),
            schema_version: VERSION,
            entries: manifest_entries,
        };
        let encoded = serde_json::to_vec(&manifest)?;
        if encoded.len() as u64 > MAX_MANIFEST {
            return Err(Error::new(
                ErrorKind::Limit,
                "Backup manifest exceeds 4 MiB",
            ));
        }
        job.check()?;
        writer
            .start_file(MANIFEST_NAME, options)
            .map_err(|error| Error::input(format!("Cannot write backup manifest: {error}")))?;
        writer.write_all(&encoded)?;
        let finished = writer
            .finish()
            .map_err(|error| Error::input(format!("Cannot finish backup: {error}")))?;
        if finished.metadata()?.len() > MAX_ARCHIVE {
            return Err(Error::new(
                ErrorKind::Limit,
                "Backup archive exceeds the 160 MiB limit",
            ));
        }
        // A second bounded tree walk catches added/removed files and directories
        // during creation. File contents are also checked by open-file metadata.
        if collect_tree(&root, job)? != source_entries {
            return Err(Error::input(
                "Source tree changed while backup was being created",
            ));
        }
        job.check()
    })?;

    job.progress(total_bytes, total_bytes);
    Ok(json!({
        "schema_version": VERSION,
        "format": FORMAT,
        "files": source_entries.iter().filter(|entry| entry.kind == EntryKind::File).count(),
        "directories": source_entries.iter().filter(|entry| entry.kind == EntryKind::Directory).count(),
        "uncompressed_bytes": total_bytes,
        "integrity": "SHA-256 per file, recorded in the embedded manifest; not authenticated",
    }))
}

pub fn verify(input: &Path, job: &Job) -> Result<Value> {
    let bytes = read_bounded(input, MAX_ARCHIVE)?;
    let archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| Error::input(format!("Invalid backup archive: {error}")))?;
    let plan = plan_archive(archive, job, false)?;
    Ok(json!({
        "schema_version": VERSION,
        "format": FORMAT,
        "verified_files": plan.files,
        "verified_directories": plan.directories,
        "verified_bytes": plan.total_bytes,
        "integrity": "SHA-256 values match the embedded manifest; manifest is not authenticated",
    }))
}

pub fn restore(input: &Path, output: &Path, job: &Job) -> Result<Value> {
    let bytes = read_bounded(input, MAX_ARCHIVE)?;
    let archive = zip::ZipArchive::new(Cursor::new(bytes.as_slice()))
        .map_err(|error| Error::input(format!("Invalid backup archive: {error}")))?;
    let plan = plan_archive(archive, job, true)?;

    if output.file_name().is_none() {
        return Err(Error::input("Choose a new restore destination directory"));
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let destination = parent.join(output.file_name().expect("checked filename"));
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(Error::input("Restore destination already exists"));
    }
    fs::create_dir(&destination)?;

    let result = (|| -> Result<()> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes.as_slice()))
            .map_err(|error| Error::input(format!("Invalid backup archive: {error}")))?;
        // Create explicit directories parent-first. Backup archives never contain
        // symlinks, and restore creates every path under a newly reserved folder.
        let mut directories = plan
            .entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Directory)
            .collect::<Vec<_>>();
        directories.sort_by_key(|entry| entry.path.components().count());
        for entry in directories {
            job.check()?;
            let target = destination.join(&entry.path);
            fs::create_dir(&target)?;
        }

        let mut completed = 0u64;
        let progress_total = plan.total_bytes.saturating_mul(2);
        job.progress(plan.total_bytes, progress_total);
        let mut buffer = [0u8; BUFFER];
        for entry in plan
            .entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::File)
        {
            job.check()?;
            let target = destination.join(&entry.path);
            let parent = target
                .parent()
                .ok_or_else(|| Error::input("Invalid restore path"))?;
            validate_created_parent(&destination, parent)?;
            let mut member = archive
                .by_index(entry.index)
                .map_err(|error| Error::input(format!("Cannot read backup member: {error}")))?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            let mut hasher = Sha256::new();
            let mut copied = 0u64;
            loop {
                job.check()?;
                let count = member
                    .read(&mut buffer)
                    .map_err(|error| Error::input(format!("Backup member read failed: {error}")))?;
                if count == 0 {
                    break;
                }
                copied += count as u64;
                if copied > entry.bytes {
                    return Err(Error::input("Backup member exceeds its declared size"));
                }
                hasher.update(&buffer[..count]);
                output.write_all(&buffer[..count])?;
                job.progress(
                    plan.total_bytes
                        .saturating_add(completed)
                        .saturating_add(copied),
                    progress_total,
                );
            }
            let actual_hash = format!("{:x}", hasher.finalize());
            if copied != entry.bytes || entry.sha256.as_deref() != Some(actual_hash.as_str()) {
                return Err(Error::input("Backup changed after verification"));
            }
            output.sync_all()?;
            completed = completed.saturating_add(copied);
        }
        job.check()
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&destination);
    }
    result?;
    let progress_total = plan.total_bytes.saturating_mul(2);
    job.progress(progress_total, progress_total);
    Ok(json!({
        "schema_version": VERSION,
        "restored_files": plan.files,
        "restored_directories": plan.directories,
        "restored_bytes": plan.total_bytes,
        "destination": destination,
    }))
}

fn collect_tree(root: &Path, job: &Job) -> Result<Vec<SourceEntry>> {
    job.progress(0, 0);
    let mut result = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((directory, depth)) = stack.pop() {
        job.check()?;
        if depth > MAX_DEPTH {
            return Err(Error::new(
                ErrorKind::Limit,
                "Backup directory depth limit exceeded",
            ));
        }
        let directory_metadata = fs::symlink_metadata(&directory)?;
        if !directory_metadata.is_dir()
            || directory_metadata.file_type().is_symlink()
            || !fs::canonicalize(&directory)?.starts_with(root)
        {
            return Err(Error::input(
                "Backup directory changed or escaped the source root",
            ));
        }
        let mut children = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            job.check()?;
            visited += 1;
            if visited > MAX_ENTRIES {
                return Err(Error::new(ErrorKind::Limit, "Backup entry limit exceeded"));
            }
            let path = child.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(Error::input("Backup source contains a symbolic link"));
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| Error::input("Backup path escaped source directory"))?;
            let relative = super::portable_relative(relative)?;
            if relative.len() > MAX_PATH {
                return Err(Error::new(
                    ErrorKind::Limit,
                    "Backup path exceeds 1,024 bytes",
                ));
            }
            if metadata.is_dir() {
                result.push(SourceEntry {
                    path: relative,
                    kind: EntryKind::Directory,
                    bytes: 0,
                    modified: metadata.modified().ok(),
                });
                stack.push((path, depth + 1));
            } else if metadata.is_file() {
                if metadata.len() > MAX_FILE {
                    return Err(Error::new(ErrorKind::Limit, "Backup file exceeds 32 MiB"));
                }
                result.push(SourceEntry {
                    path: relative,
                    kind: EntryKind::File,
                    bytes: metadata.len(),
                    modified: metadata.modified().ok(),
                });
            } else {
                return Err(Error::input("Backup source contains a special file"));
            }
        }
    }
    result.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(result)
}

fn same_file_identity(path: &Path, opened: &File) -> Result<bool> {
    // Use stable cross-platform handle APIs, including on Windows where the
    // corresponding standard-library MetadataExt methods remain unstable.
    let opened_handle = same_file::Handle::from_file(opened.try_clone()?)?;
    let path_handle = same_file::Handle::from_path(path)?;
    Ok(opened_handle == path_handle)
}

fn plan_archive<R: Read + std::io::Seek>(
    mut archive: zip::ZipArchive<R>,
    job: &Job,
    includes_restore_pass: bool,
) -> Result<RestorePlan> {
    if archive.len() > MAX_ENTRIES + 1 {
        return Err(Error::new(
            ErrorKind::Limit,
            "Backup entry count limit exceeded",
        ));
    }
    let mut manifest_count = 0usize;
    let mut archive_names = HashSet::new();
    let mut manifest_bytes = None;
    let mut expanded = 0u64;
    for index in 0..archive.len() {
        job.check()?;
        let member = archive
            .by_index(index)
            .map_err(|error| Error::input(format!("Invalid backup entry: {error}")))?;
        let name = member
            .name()
            .map_err(|error| Error::input(format!("Invalid backup entry name: {error}")))?
            .to_string();
        if name.len() > MAX_PATH + PAYLOAD_PREFIX.len() + 1 || !archive_names.insert(name.clone()) {
            return Err(Error::input(
                "Backup contains a duplicate or oversized path",
            ));
        }
        if member.encrypted()
            || member.is_symlink()
            || member
                .unix_mode()
                .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000 | 0o040000))
        {
            return Err(Error::input(
                "Backup contains an encrypted link or special entry",
            ));
        }
        if name == MANIFEST_NAME {
            manifest_count += 1;
            if member.is_dir() || member.size() > MAX_MANIFEST {
                return Err(Error::input("Invalid backup manifest entry"));
            }
            let expected_size = member.size();
            let mut data = Vec::with_capacity(expected_size as usize);
            member
                .take(MAX_MANIFEST + 1)
                .read_to_end(&mut data)
                .map_err(|error| Error::input(format!("Cannot read backup manifest: {error}")))?;
            if data.len() as u64 > MAX_MANIFEST || data.len() as u64 != expected_size {
                return Err(Error::input("Backup manifest size mismatch"));
            }
            manifest_bytes = Some(data);
            continue;
        }
        if !name.starts_with(PAYLOAD_PREFIX) {
            return Err(Error::input("Backup contains an unexpected entry"));
        }
        if member.size() > MAX_FILE || member.size() > MAX_TOTAL.saturating_sub(expanded) {
            return Err(Error::new(
                ErrorKind::Limit,
                "Backup expansion limit exceeded",
            ));
        }
        expanded += member.size();
    }
    if manifest_count != 1 {
        return Err(Error::input("Backup must contain exactly one manifest"));
    }
    let manifest: BackupManifest = serde_json::from_slice(
        manifest_bytes
            .as_deref()
            .ok_or_else(|| Error::input("Backup manifest is missing"))?,
    )
    .map_err(|error| Error::input(format!("Invalid backup manifest: {error}")))?;
    if manifest.format != FORMAT || manifest.schema_version != VERSION {
        return Err(Error::input("Unsupported backup format or version"));
    }
    if manifest.entries.len() > MAX_ENTRIES {
        return Err(Error::new(
            ErrorKind::Limit,
            "Backup manifest entry limit exceeded",
        ));
    }

    let mut records = HashMap::with_capacity(manifest.entries.len());
    let mut total_bytes = 0u64;
    let mut files = 0usize;
    let mut directories = 0usize;
    for entry in manifest.entries {
        job.check()?;
        let normalized = super::archive_name(&entry.path, entry.kind == EntryKind::Directory)
            .map_err(|_| Error::input("Backup manifest contains an unsafe path"))?;
        if super::portable_relative(&normalized)? != entry.path || entry.path.len() > MAX_PATH {
            return Err(Error::input("Backup manifest path is not canonical"));
        }
        match entry.kind {
            EntryKind::File => {
                let valid_hash = entry.sha256.as_deref().is_some_and(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                });
                if !valid_hash {
                    return Err(Error::input("Backup file has an invalid SHA-256 value"));
                }
                if entry.bytes > MAX_FILE || entry.bytes > MAX_TOTAL.saturating_sub(total_bytes) {
                    return Err(Error::new(
                        ErrorKind::Limit,
                        "Backup manifest size limit exceeded",
                    ));
                }
                total_bytes += entry.bytes;
                files += 1;
            }
            EntryKind::Directory => {
                if entry.bytes != 0 || entry.sha256.is_some() {
                    return Err(Error::input("Backup directory record contains file data"));
                }
                directories += 1;
            }
        }
        if records.insert(entry.path.clone(), entry).is_some() {
            return Err(Error::input("Backup manifest contains duplicate paths"));
        }
    }
    check_case_collisions(records.keys().map(String::as_str))?;
    validate_path_relationships(&records)?;

    let mut entries = Vec::with_capacity(records.len());
    let mut matched = HashSet::new();
    let mut verified_bytes = 0u64;
    let progress_total = total_bytes.saturating_mul(if includes_restore_pass { 2 } else { 1 });
    for index in 0..archive.len() {
        job.check()?;
        let mut member = archive
            .by_index(index)
            .map_err(|error| Error::input(format!("Invalid backup entry: {error}")))?;
        let name = member
            .name()
            .map_err(|error| Error::input(format!("Invalid backup entry name: {error}")))?
            .into_owned();
        if name == MANIFEST_NAME {
            continue;
        }
        let payload_name = name
            .strip_prefix(PAYLOAD_PREFIX)
            .ok_or_else(|| Error::input("Backup contains an unexpected entry"))?;
        let is_directory = member.is_dir();
        let path = payload_name.strip_suffix('/').unwrap_or(payload_name);
        let record = records
            .get(path)
            .ok_or_else(|| Error::input("Backup payload is absent from its manifest"))?;
        if !matched.insert(path.to_string())
            || (record.kind == EntryKind::Directory) != is_directory
            || record.bytes != member.size()
        {
            return Err(Error::input("Backup entry does not match its manifest"));
        }
        if is_directory {
            entries.push(RestoreEntry {
                index,
                path: super::archive_name(path, true)?,
                kind: EntryKind::Directory,
                bytes: 0,
                sha256: None,
            });
            continue;
        }
        let expected_hash = record.sha256.as_deref().expect("validated file hash");
        let mut hasher = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; BUFFER];
        loop {
            job.check()?;
            let count = member.read(&mut buffer).map_err(|error| {
                Error::input(format!("Backup file integrity check failed: {error}"))
            })?;
            if count == 0 {
                break;
            }
            copied += count as u64;
            if copied > record.bytes {
                return Err(Error::input("Backup file exceeds its manifest size"));
            }
            hasher.update(&buffer[..count]);
            job.progress(verified_bytes.saturating_add(copied), progress_total);
        }
        if copied != record.bytes || format!("{:x}", hasher.finalize()) != expected_hash {
            return Err(Error::input("Backup file SHA-256 does not match manifest"));
        }
        verified_bytes = verified_bytes.saturating_add(copied);
        job.progress(verified_bytes, progress_total);
        entries.push(RestoreEntry {
            index,
            path: super::archive_name(path, false)?,
            kind: EntryKind::File,
            bytes: record.bytes,
            sha256: Some(expected_hash.to_string()),
        });
    }
    if matched.len() != records.len() {
        return Err(Error::input(
            "Backup manifest lists an entry absent from the archive",
        ));
    }
    Ok(RestorePlan {
        entries,
        total_bytes,
        files,
        directories,
    })
}

fn validate_path_relationships(records: &HashMap<String, ManifestEntry>) -> Result<()> {
    for (path, entry) in records {
        let candidate = Path::new(path);
        if entry.kind == EntryKind::File
            && records
                .iter()
                .any(|(other, _)| Path::new(other).starts_with(candidate) && other != path)
        {
            return Err(Error::input(
                "Backup file path conflicts with a nested entry",
            ));
        }
        let mut parent = candidate.parent();
        while let Some(parent_path) = parent {
            let Some(parent_name) = parent_path.to_str().filter(|value| !value.is_empty()) else {
                break;
            };
            if !records
                .get(parent_name)
                .is_some_and(|record| record.kind == EntryKind::Directory)
            {
                return Err(Error::input("Backup entry is missing a parent directory"));
            }
            parent = parent_path.parent();
        }
    }
    Ok(())
}

fn check_case_collisions<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut folded = HashSet::new();
    for path in paths {
        if !folded.insert(path.to_lowercase()) {
            return Err(Error::input(
                "Backup contains paths that collide on case-insensitive filesystems",
            ));
        }
    }
    Ok(())
}

fn validate_created_parent(root: &Path, parent: &Path) -> Result<()> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| Error::input("Restore path escaped destination"))?;
    let mut current = root.to_path_buf();
    let root_metadata = fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(Error::input(
            "Restore destination is no longer a regular directory",
        ));
    }
    for component in relative.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::input(
                "Restore destination contains a symlink or non-directory",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use localwright_core::Request;

    fn request_tree(root: &Path) {
        fs::create_dir_all(root.join("nested/empty")).unwrap();
        fs::write(root.join("alpha.txt"), b"alpha original").unwrap();
        fs::write(root.join("nested/data.bin"), (0..128u8).collect::<Vec<_>>()).unwrap();
    }

    #[test]
    fn backup_verify_restore_round_trip_preserves_source_and_empty_directories() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let backup = temp.path().join("source.fsbackup");
        let restored = temp.path().join("restored");
        request_tree(&source);
        let original = fs::read(source.join("alpha.txt")).unwrap();
        let created = super::super::handle(
            Request {
                operation: "backup-create".into(),
                input: source.clone(),
                output: backup.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(created.written.as_ref(), Some(&backup));
        assert_eq!(
            serde_json::from_str::<Value>(&created.preview).unwrap()["files"],
            2
        );
        let verified = super::super::handle(
            Request {
                operation: "backup-verify".into(),
                input: backup.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&verified.preview).unwrap()["verified_files"],
            2
        );
        let restored_report = super::super::handle(
            Request {
                operation: "backup-restore".into(),
                input: backup.clone(),
                output: restored.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(restored_report.written.as_ref(), Some(&restored));
        assert_eq!(
            serde_json::from_str::<Value>(&restored_report.preview).unwrap()["restored_files"],
            2
        );
        assert_eq!(fs::read(restored.join("alpha.txt")).unwrap(), original);
        assert!(restored.join("nested/empty").is_dir());
        assert_eq!(
            fs::read(source.join("nested/data.bin")).unwrap(),
            (0..128u8).collect::<Vec<_>>()
        );
        assert!(restore(&backup, &restored, &Job::new()).is_err());
    }

    #[test]
    fn rejects_corrupted_payload_and_path_escape_before_restore() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let backup = temp.path().join("source.fsbackup");
        request_tree(&source);
        create(&source, &backup, &Job::new()).unwrap();
        let mut bytes = fs::read(&backup).unwrap();
        let needle = b"payload/alpha.txt";
        let name = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        let local = bytes[..name]
            .windows(4)
            .rposition(|window| window == [0x50, 0x4b, 0x03, 0x04])
            .unwrap();
        let name_length = u16::from_le_bytes([bytes[local + 26], bytes[local + 27]]) as usize;
        let extra_length = u16::from_le_bytes([bytes[local + 28], bytes[local + 29]]) as usize;
        let data_offset = local + 30 + name_length + extra_length;
        bytes[data_offset] ^= 0x20;
        let corrupt = temp.path().join("corrupt.fsbackup");
        fs::write(&corrupt, bytes).unwrap();
        assert!(verify(&corrupt, &Job::new()).is_err());
        let destination = temp.path().join("must-not-appear");
        assert!(restore(&corrupt, &destination, &Job::new()).is_err());
        assert!(!destination.exists());

        let malicious = temp.path().join("escape.fsbackup");
        write_path_escape_archive(&malicious);
        assert!(verify(&malicious, &Job::new()).is_err());
        assert!(restore(&malicious, &destination, &Job::new()).is_err());
        assert!(!destination.exists());
    }

    fn write_path_escape_archive(path: &Path) {
        let manifest = BackupManifest {
            format: FORMAT.into(),
            schema_version: VERSION,
            entries: vec![ManifestEntry {
                path: "../escape.txt".into(),
                kind: EntryKind::File,
                bytes: 3,
                sha256: Some(format!("{:x}", Sha256::digest(b"bad"))),
            }],
        };
        let file = File::create(path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file(MANIFEST_NAME, options).unwrap();
        archive
            .write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        archive
            .start_file("payload/../escape.txt", options)
            .unwrap();
        archive.write_all(b"bad").unwrap();
        archive.finish().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks_and_cancelled_jobs_without_publishing_backup() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(temp.path().join("outside"), b"private").unwrap();
        symlink(temp.path().join("outside"), source.join("link")).unwrap();
        let backup = temp.path().join("source.fsbackup");
        assert!(create(&source, &backup, &Job::new()).is_err());
        fs::remove_file(source.join("link")).unwrap();
        let cancelled = Job::new();
        cancelled.cancel();
        assert!(create(&source, &backup, &cancelled).is_err());
        assert!(!backup.exists());
    }
}
