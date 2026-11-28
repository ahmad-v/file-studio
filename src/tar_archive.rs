//! Bounded, path-safe TAR workflows. TAR has header checksums but no standard
//! checksum for file contents; `tar-test` therefore validates headers and
//! complete member lengths, not the authenticity or integrity of payload bytes.

use localwright_core::{write_new, Error, ErrorKind, Job, Result};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

const MAX_ARCHIVE_BYTES: u64 = 160 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_PATH_BYTES: usize = 1024;
const BUFFER_SIZE: usize = 32 * 1024;

#[derive(Clone, Debug)]
struct Member {
    index: usize,
    path: PathBuf,
    directory: bool,
    size: u64,
}

fn relative_member_path(name: &str, directory: bool) -> Result<PathBuf> {
    let mut body = name;
    while let Some(stripped) = body.strip_prefix("./") {
        body = stripped;
    }
    if directory && (body.is_empty() || body == ".") {
        return Ok(PathBuf::new());
    }
    super::archive_name(body, directory)
}

fn open_archive(path: &Path) -> Result<(File, u64, Option<SystemTime>)> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Error::input("Choose a regular, non-symlink TAR archive"));
    }
    if before.len() > MAX_ARCHIVE_BYTES {
        return Err(Error::new(ErrorKind::Limit, "TAR archive exceeds 160 MiB"));
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.len() != before.len()
        || opened.modified().ok() != before.modified().ok()
    {
        return Err(Error::input(
            "TAR archive changed while it was being opened",
        ));
    }
    Ok((file, opened.len(), opened.modified().ok()))
}

fn ensure_unchanged(
    file: &File,
    path: &Path,
    size: u64,
    modified: Option<SystemTime>,
) -> Result<()> {
    let opened = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    if opened.len() != size
        || current.len() != size
        || modified.is_some_and(|expected| opened.modified().ok() != Some(expected))
        || opened.modified().ok() != current.modified().ok()
        || current.file_type().is_symlink()
    {
        return Err(Error::input(
            "TAR archive changed while it was being processed",
        ));
    }
    Ok(())
}

fn plan_archive(
    path: &Path,
    job: &Job,
    drain_payloads: bool,
) -> Result<(File, Vec<Member>, u64, u64, Option<SystemTime>)> {
    let (file, archive_bytes, modified) = open_archive(path)?;
    let mut archive = tar::Archive::new(file);
    let mut members = Vec::new();
    let mut names = std::collections::HashSet::new();
    let mut total = 0u64;
    let entries = archive
        .entries()
        .map_err(|error| Error::input(format!("Invalid TAR archive: {error}")))?;

    for entry in entries {
        job.check()?;
        let mut entry =
            entry.map_err(|error| Error::input(format!("Invalid TAR entry: {error}")))?;
        if members.len() >= MAX_ENTRIES {
            return Err(Error::new(ErrorKind::Limit, "TAR entry limit exceeded"));
        }
        let entry_type = entry.header().entry_type();
        let directory = match entry_type {
            tar::EntryType::Regular => false,
            tar::EntryType::Directory => true,
            _ => {
                return Err(Error::input(
                    "TAR contains a link, sparse file, device, or unsupported entry type",
                ))
            }
        };
        let name = entry
            .path()
            .map_err(|error| Error::input(format!("Invalid TAR path: {error}")))?;
        let name = name
            .to_str()
            .ok_or_else(|| Error::input("TAR path is not valid Unicode"))?;
        if name.len() > MAX_PATH_BYTES {
            return Err(Error::new(ErrorKind::Limit, "TAR path exceeds 1,024 bytes"));
        }
        let relative = relative_member_path(name, directory)?;
        let normalized = relative.to_string_lossy().replace('\\', "/");
        if !names.insert(normalized) {
            return Err(Error::input("TAR contains duplicate paths"));
        }
        let size = entry.size();
        if directory && size != 0 {
            return Err(Error::input("TAR directory entry has unexpected data"));
        }
        if !directory {
            if size > MAX_ENTRY_BYTES || size > MAX_TOTAL_BYTES.saturating_sub(total) {
                return Err(Error::new(ErrorKind::Limit, "TAR expansion limit exceeded"));
            }
            total += size;
        }
        if drain_payloads && !directory {
            stream_entry(&mut entry, size, &mut io::sink(), members.len() + 1, job)?;
        }
        members.push(Member {
            index: members.len(),
            path: relative,
            directory,
            size,
        });
    }
    for member in &members {
        if !member.directory
            && members
                .iter()
                .any(|other| other.path.starts_with(&member.path) && other.path != member.path)
        {
            return Err(Error::input("TAR file path conflicts with a nested entry"));
        }
    }
    let file = archive.into_inner();
    ensure_unchanged(&file, path, archive_bytes, modified)?;
    Ok((file, members, total, archive_bytes, modified))
}

fn stream_entry(
    reader: &mut impl Read,
    expected: u64,
    output: &mut impl Write,
    number: usize,
    job: &Job,
) -> Result<()> {
    let mut count = 0u64;
    let mut buffer = [0; BUFFER_SIZE];
    loop {
        job.check()?;
        let read = reader
            .read(&mut buffer)
            .map_err(|error| Error::input(format!("TAR entry {number} cannot be read: {error}")))?;
        if read == 0 {
            break;
        }
        let read = read as u64;
        if read > expected.saturating_sub(count) {
            return Err(Error::input(format!(
                "TAR entry {number} exceeds its declared size"
            )));
        }
        output.write_all(&buffer[..read as usize])?;
        count += read;
        job.progress(count, expected);
    }
    if count != expected {
        return Err(Error::input(format!("TAR entry {number} is truncated")));
    }
    Ok(())
}

pub(super) fn list(path: &Path, job: &Job) -> Result<Value> {
    let (_, members, total, archive_bytes, _) = plan_archive(path, job, false)?;
    let entries = members
        .iter()
        .map(|member| {
            let path = if member.path.as_os_str().is_empty() {
                ".".to_string()
            } else {
                member.path.to_string_lossy().into_owned()
            };
            json!({
                "index": member.index + 1,
                "path": path,
                "kind": if member.directory { "directory" } else { "file" },
                "bytes": member.size,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema_version": 1,
        "format": "tar",
        "archive_bytes": archive_bytes,
        "entries": entries,
        "regular_files": members.iter().filter(|member| !member.directory).count(),
        "declared_uncompressed_bytes": total,
        "payloads_read": false,
    }))
}

pub(super) fn test(path: &Path, job: &Job) -> Result<Value> {
    let (_, members, total, archive_bytes, _) = plan_archive(path, job, true)?;
    Ok(json!({
        "schema_version": 1,
        "format": "tar",
        "archive_bytes": archive_bytes,
        "entries_checked": members.len(),
        "regular_files": members.iter().filter(|member| !member.directory).count(),
        "uncompressed_bytes_read": total,
        "payload_checksums_available": false,
    }))
}

pub(super) fn create_directory(input: &Path, output: &Path, job: &Job) -> Result<Value> {
    if !output
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("tar"))
    {
        return Err(Error::input("Choose .tar output"));
    }
    let metadata = fs::symlink_metadata(input)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::input("Choose a non-symlink directory"));
    }
    let root = fs::canonicalize(input)?;
    let rows = super::scan(&root, job)?.into_complete_files()?;
    if rows.len() > MAX_ENTRIES {
        return Err(Error::new(ErrorKind::Limit, "TAR entry limit exceeded"));
    }
    let mut total = 0u64;
    let mut names = std::collections::HashSet::new();
    let mut paths = Vec::with_capacity(rows.len());
    for row in &rows {
        let relative = Path::new(row["path"].as_str().unwrap_or_default());
        let archive_path = super::portable_relative(relative)?;
        if archive_path.len() > MAX_PATH_BYTES || !names.insert(archive_path.clone()) {
            return Err(Error::input(
                "Directory has an invalid or duplicate TAR path",
            ));
        }
        let bytes = row["bytes"].as_u64().unwrap_or(u64::MAX);
        if bytes > MAX_ENTRY_BYTES || bytes > MAX_TOTAL_BYTES.saturating_sub(total) {
            return Err(Error::new(
                ErrorKind::Limit,
                "TAR input size limit exceeded",
            ));
        }
        total += bytes;
        paths.push((archive_path, relative.to_path_buf(), bytes));
    }

    let mut file_count = 0usize;
    write_new(output, |file| {
        let mut builder = tar::Builder::new(file);
        for (archive_path, relative, expected_size) in &paths {
            job.check()?;
            let path = root.join(relative);
            if !fs::canonicalize(&path)?.starts_with(&root) {
                return Err(Error::input(
                    "File escaped the selected directory during TAR creation",
                ));
            }
            let before = fs::symlink_metadata(&path)?;
            if !before.is_file()
                || before.file_type().is_symlink()
                || before.len() != *expected_size
            {
                return Err(Error::input("Directory changed during TAR creation"));
            }
            let mut source = File::open(&path)?;
            let opened = source.metadata()?;
            if opened.len() != before.len() || opened.modified().ok() != before.modified().ok() {
                return Err(Error::input("Source changed while opening TAR member"));
            }
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(*expected_size);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            let mut reader = CheckedReader {
                source: &mut source,
                job,
                read: 0,
                expected: *expected_size,
            };
            builder
                .append_data(&mut header, archive_path, &mut reader)
                .map_err(|error| Error::input(format!("TAR creation failed: {error}")))?;
            let bytes_read = reader.read;
            drop(reader);
            if bytes_read != *expected_size
                || source.metadata()?.modified().ok() != opened.modified().ok()
            {
                return Err(Error::input("Source changed during TAR creation"));
            }
            file_count += 1;
        }
        job.check()?;
        builder
            .finish()
            .map_err(|error| Error::input(format!("TAR finalization failed: {error}")))?;
        Ok(())
    })?;
    Ok(json!({
        "schema_version": 1,
        "format": "tar",
        "regular_files": file_count,
        "uncompressed_bytes": total,
        "archive_bytes": fs::metadata(output)?.len(),
    }))
}

struct CheckedReader<'a> {
    source: &'a mut File,
    job: &'a Job,
    read: u64,
    expected: u64,
}

impl Read for CheckedReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.job
            .check()
            .map_err(|error| io::Error::other(error.message))?;
        let count = self.source.read(buffer)?;
        self.read = self.read.saturating_add(count as u64);
        if self.read > self.expected {
            return Err(io::Error::other("TAR source grew during creation"));
        }
        self.job.progress(self.read, self.expected);
        Ok(count)
    }
}

fn destination_root(output: &Path) -> Result<PathBuf> {
    if output.exists() || output.file_name().is_none() {
        return Err(Error::input("Choose a new TAR extraction destination"));
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let root = parent.join(output.file_name().expect("checked filename"));
    if root.exists() {
        return Err(Error::input("TAR extraction destination already exists"));
    }
    fs::create_dir(&root)?;
    fs::canonicalize(&root).map_err(Error::from)
}

fn extract_member<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    member: &Member,
    root: &Path,
    job: &Job,
) -> Result<()> {
    let target = root.join(&member.path);
    if member.directory {
        fs::create_dir_all(&target)?;
        let canonical = fs::canonicalize(&target)?;
        if !canonical.starts_with(root) {
            return Err(Error::input("TAR extraction path escaped its destination"));
        }
        stream_entry(entry, member.size, &mut io::sink(), member.index + 1, job)?;
        return Ok(());
    }
    let parent = target
        .parent()
        .ok_or_else(|| Error::input("Invalid TAR output path"))?;
    fs::create_dir_all(parent)?;
    if !fs::canonicalize(parent)?.starts_with(root) {
        return Err(Error::input("TAR extraction path escaped its destination"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)?;
    stream_entry(entry, member.size, &mut file, member.index + 1, job)?;
    file.flush()?;
    Ok(())
}

pub(super) fn extract_all(input: &Path, output: &Path, job: &Job) -> Result<Value> {
    let (mut file, members, total, archive_bytes, modified) = plan_archive(input, job, false)?;
    if members.iter().all(|member| member.directory) {
        // Empty archives are valid, but an archive with no usable entries is
        // more likely to be a format mismatch than a useful extraction.
        return Err(Error::input("TAR archive contains no regular files"));
    }
    let root = destination_root(output)?;
    let result = (|| -> Result<()> {
        file.seek(SeekFrom::Start(0))?;
        let mut archive = tar::Archive::new(file);
        let mut entries = archive
            .entries()
            .map_err(|error| Error::input(format!("Cannot reopen TAR members: {error}")))?;
        for member in &members {
            job.check()?;
            let mut entry = entries
                .next()
                .ok_or_else(|| Error::input("TAR member disappeared during extraction"))?
                .map_err(|error| Error::input(format!("Cannot read TAR member: {error}")))?;
            extract_member(&mut entry, member, &root, job)?;
        }
        drop(entries);
        let file = archive.into_inner();
        ensure_unchanged(&file, input, archive_bytes, modified)?;
        job.check()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&root);
    }
    result?;
    Ok(json!({
        "schema_version": 1,
        "format": "tar",
        "entries_extracted": members.len(),
        "regular_files": members.iter().filter(|member| !member.directory).count(),
        "uncompressed_bytes": total,
        "archive_bytes": archive_bytes,
        "destination": root,
        "source_unchanged": true,
    }))
}

pub(super) fn extract_entry(
    input: &Path,
    output: &Path,
    parameter: &str,
    job: &Job,
) -> Result<Value> {
    let selected = parameter
        .trim()
        .parse::<usize>()
        .map_err(|_| Error::input("Enter the one-based TAR entry number from List TAR contents"))?;
    if selected == 0 {
        return Err(Error::input("TAR entry numbers start at 1"));
    }
    let (mut file, members, _, archive_bytes, modified) = plan_archive(input, job, false)?;
    let member = members
        .get(selected - 1)
        .ok_or_else(|| Error::input("TAR entry number is out of range"))?;
    if member.directory {
        return Err(Error::input("Select a regular file entry"));
    }
    if output.exists() {
        return Err(Error::input("Choose a new output file"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut archive = tar::Archive::new(file);
    write_new(output, |file| {
        extract_member_to_file(&mut archive, member, file, job)
    })?;
    let file = archive.into_inner();
    ensure_unchanged(&file, input, archive_bytes, modified)?;
    Ok(json!({
        "schema_version": 1,
        "format": "tar",
        "entry": selected,
        "path": member.path.to_string_lossy(),
        "bytes": member.size,
        "archive_bytes": archive_bytes,
        "source_unchanged": true,
        "archive_mtime_recorded": modified.is_some(),
    }))
}

fn extract_member_to_file(
    archive: &mut tar::Archive<File>,
    member: &Member,
    file: &mut File,
    job: &Job,
) -> Result<()> {
    let mut entries = archive
        .entries()
        .map_err(|error| Error::input(format!("Cannot reopen TAR members: {error}")))?;
    let mut entry = entries
        .nth(member.index)
        .ok_or_else(|| Error::input("TAR member disappeared during extraction"))?
        .map_err(|error| Error::input(format!("Cannot read TAR member: {error}")))?;
    stream_entry(&mut entry, member.size, file, member.index + 1, job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::tempdir;

    fn fixture(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            for (name, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, *name, Cursor::new(*content))
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        bytes
    }

    fn forge_first_member_path(bytes: &mut [u8], name: &[u8]) {
        assert!(name.len() < 100);
        let header = &mut bytes[..512];
        header[..100].fill(0);
        header[..name.len()].copy_from_slice(name);
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let encoded = format!("{checksum:06o}\0 ");
        assert_eq!(encoded.len(), 8);
        header[148..156].copy_from_slice(encoded.as_bytes());
    }

    #[test]
    fn standard_dot_prefixes_are_normalized_but_traversal_is_rejected() {
        assert_eq!(
            relative_member_path("./nested/file.txt", false).unwrap(),
            PathBuf::from("nested/file.txt")
        );
        assert_eq!(relative_member_path("./", true).unwrap(), PathBuf::new());
        assert!(relative_member_path("./../outside.txt", false).is_err());
    }

    #[test]
    fn list_test_and_extract_cover_regular_files() {
        let directory = tempdir().unwrap();
        let archive = directory.path().join("sample.tar");
        fs::write(
            &archive,
            fixture(&[("nested/a.txt", b"alpha"), ("b.txt", b"beta")]),
        )
        .unwrap();
        let listing = list(&archive, &Job::new()).unwrap();
        assert_eq!(listing["regular_files"], 2);
        assert_eq!(listing["payloads_read"], false);
        let checked = test(&archive, &Job::new()).unwrap();
        assert_eq!(checked["uncompressed_bytes_read"], 9);

        let selected = directory.path().join("selected.txt");
        extract_entry(&archive, &selected, "2", &Job::new()).unwrap();
        assert_eq!(fs::read(&selected).unwrap(), b"beta");
        assert!(extract_entry(&archive, &selected, "2", &Job::new()).is_err());

        let destination = directory.path().join("out");
        extract_all(&archive, &destination, &Job::new()).unwrap();
        assert_eq!(
            fs::read(destination.join("nested/a.txt")).unwrap(),
            b"alpha"
        );
        assert_eq!(fs::read(destination.join("b.txt")).unwrap(), b"beta");
        assert!(extract_all(&archive, &destination, &Job::new()).is_err());
    }

    #[test]
    fn directory_creation_is_bounded_and_preserves_sources() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/a.txt"), b"alpha").unwrap();
        fs::write(source.join("b.txt"), b"beta").unwrap();
        let archive = directory.path().join("created.tar");

        let report = create_directory(&source, &archive, &Job::new()).unwrap();
        assert_eq!(report["regular_files"], 2);
        assert_eq!(fs::read(source.join("nested/a.txt")).unwrap(), b"alpha");
        assert_eq!(
            test(&archive, &Job::new()).unwrap()["uncompressed_bytes_read"],
            9
        );
        assert!(create_directory(&source, &archive, &Job::new()).is_err());

        let restored = directory.path().join("restored");
        extract_all(&archive, &restored, &Job::new()).unwrap();
        assert_eq!(fs::read(restored.join("nested/a.txt")).unwrap(), b"alpha");
    }

    #[test]
    fn tar_operations_are_reachable_through_the_registered_handler() {
        use localwright_core::Request;

        let directory = tempdir().unwrap();
        let source = directory.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("note.txt"), b"native workflow").unwrap();
        let archive = directory.path().join("source.tar");
        for id in [
            "tar-list",
            "tar-test",
            "tar-create-directory",
            "tar-extract-entry",
            "tar-extract-all",
        ] {
            assert!(crate::OPERATIONS.iter().any(|operation| operation.id == id));
        }

        let created = crate::handle(
            Request {
                operation: "tar-create-directory".into(),
                input: source,
                output: archive.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(created.written, Some(archive.clone()));
        let listed = crate::handle(
            Request {
                operation: "tar-list".into(),
                input: archive.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let report: Value = serde_json::from_str(&listed.preview).unwrap();
        assert_eq!(report["entries"][0]["path"], "note.txt");
        let checked = crate::handle(
            Request {
                operation: "tar-test".into(),
                input: archive.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert!(checked.preview.contains("uncompressed_bytes_read"));
        let output = directory.path().join("restored.txt");
        crate::handle(
            Request {
                operation: "tar-extract-entry".into(),
                input: archive,
                output: output.clone(),
                parameter: "1".into(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(fs::read(output).unwrap(), b"native workflow");
    }

    #[test]
    fn unsafe_paths_are_rejected_before_extraction() {
        let directory = tempdir().unwrap();
        let archive = directory.path().join("traversal.tar");
        let mut bytes = fixture(&[("safe.txt", b"bad")]);
        forge_first_member_path(&mut bytes, b"../outside.txt");
        fs::write(&archive, bytes).unwrap();
        assert!(list(&archive, &Job::new()).is_err());
        let destination = directory.path().join("out");
        assert!(extract_all(&archive, &destination, &Job::new()).is_err());
        assert!(!destination.exists());
        assert!(!directory.path().join("outside.txt").exists());
    }

    #[test]
    fn links_are_rejected() {
        let directory = tempdir().unwrap();
        let archive = directory.path().join("link.tar");
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            builder.append_link(&mut header, "link", "target").unwrap();
            builder.finish().unwrap();
        }
        fs::write(&archive, bytes).unwrap();
        assert!(list(&archive, &Job::new()).is_err());
        assert!(test(&archive, &Job::new()).is_err());
        assert!(extract_all(&archive, &directory.path().join("out"), &Job::new()).is_err());
    }

    #[test]
    fn malformed_and_truncated_archives_are_rejected() {
        let directory = tempdir().unwrap();
        let archive = directory.path().join("bad.tar");
        fs::write(&archive, b"not a tar archive").unwrap();
        assert!(list(&archive, &Job::new()).is_err());

        fs::write(&archive, fixture(&[("file.txt", b"complete")])).unwrap();
        let mut bytes = fs::read(&archive).unwrap();
        bytes.truncate(515);
        fs::write(&archive, bytes).unwrap();
        assert!(test(&archive, &Job::new()).is_err());
        let destination = directory.path().join("partial");
        assert!(extract_all(&archive, &destination, &Job::new()).is_err());
        assert!(!destination.exists());
    }
}
