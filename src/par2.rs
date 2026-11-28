//! Bounded PAR2 recovery workflows backed by the `parmesan-par2` implementation.
//!
//! This module deliberately keeps PAR2 behind a small application boundary:
//! the toolkit does not implement Reed-Solomon arithmetic or packet parsing.
//! Repair output is always staged and copied to a newly created destination;
//! source files and PAR2 sets are never modified.

use localwright_core::{Error, ErrorKind, Job, Result};
use parmesan::{
    create::{
        self, CreateCancellation, CreateEvent, CreateRequest, OutputPolicy, Recovery,
    },
    recovery_set::RecoverySet,
    repair::{self, RepairOptions},
    verify::{self, FileStatus},
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

const MAX_PAR2_SET_FILES: usize = 256;
const MAX_PAR2_SET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECOVERED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CREATE_MEMORY: usize = 256 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 1024 * 1024;

/// Create a PAR2 recovery set for one regular file.
///
/// `output_dir` is an existing output directory. Existing recovery files are
/// rejected by the underlying engine. The parameter is an integer recovery
/// percentage in the range 1–50; an empty parameter selects 10 percent.
pub fn create_for_file(
    input: &Path,
    output_dir: &Path,
    parameter: &str,
    job: &Job,
) -> Result<Value> {
    job.check()?;
    let metadata = fs::symlink_metadata(input)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::input("Choose one regular, non-symlink source file"));
    }
    let recovery_percent = parse_recovery_percent(parameter)?;
    let output_metadata = fs::symlink_metadata(output_dir)
        .map_err(|error| Error::input(format!("Choose an existing output directory: {error}")))?;
    if !output_metadata.is_dir() || output_metadata.file_type().is_symlink() {
        return Err(Error::input("Choose an existing, non-symlink output directory"));
    }

    let request = CreateRequest::from_paths([input])
        .output_dir(output_dir)
        .recovery(Recovery::Percentage(recovery_percent))
        .memory_limit(MAX_CREATE_MEMORY)
        .output_policy(OutputPolicy::FailIfExists);
    // Creating the runtime can fail in constrained hosts. Do this before the
    // cancellation watcher starts so a setup error cannot leak a waiting thread.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| Error::engine(format!("Could not initialize PAR2 runtime: {error}")))?;
    let cancellation = CreateCancellation::new();
    let watch_done = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&watch_done);
    let watched_job = job.clone();
    let watched_cancellation = cancellation.clone();
    let watcher = thread::spawn(move || {
        while !done.load(Ordering::Acquire) {
            if watched_job.check().is_err() {
                watched_cancellation.cancel();
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| Error::engine(format!("Could not initialize PAR2 runtime: {error}")))?;
    let result = runtime.block_on(create::create_with_progress_and_cancellation(
        request,
        &cancellation,
        |event| match event {
            CreateEvent::Planned {
                input_bytes,
                ..
            } => job.progress(0, input_bytes.saturating_mul(2)),
            CreateEvent::BytesRead { bytes_read, .. } => {
                job.progress(bytes_read, 0);
            }
            CreateEvent::IndexWritten { .. } | CreateEvent::VolumeWritten { .. } => {
                // Output publication is tracked as indeterminate because a
                // low-memory set may require multiple complete input passes.
                job.progress(0, 0);
            }
            _ => {}
        },
    ));
    watch_done.store(true, Ordering::Release);
    let _ = watcher.join();
    let report = result.map_err(|error| {
        if job.check().is_err() {
            Error::new(ErrorKind::Cancelled, "PAR2 creation cancelled")
        } else {
            Error::engine(format!("PAR2 creation failed: {error}"))
        }
    })?;
    Ok(json!({
        "schema_version": 1,
        "recovery_set_id": hex(&report.recovery_set_id),
        "slice_size_bytes": report.geometry.slice_size,
        "input_slices": report.geometry.input_slices,
        "recovery_blocks": report.geometry.recovery_blocks,
        "index": report.index_path,
        "volumes": report.volume_paths,
        "memory_budget_bytes": MAX_CREATE_MEMORY,
    }))
}

/// Verify a PAR2 set against a directory without writing any files.
pub fn verify_set(index_path: &Path, source_dir: &Path, job: &Job) -> Result<Value> {
    validate_index_and_set_size(index_path)?;
    validate_directory(source_dir, "Choose a regular directory to verify against")?;
    job.check()?;
    let set = RecoverySet::load_metadata(index_path)
        .map_err(|error| Error::engine(format!("Could not read PAR2 recovery set: {error}")))?;
    validate_source_members(&set, source_dir)?;
    let report = verify::verify_with_progress(&set, source_dir, |progress| {
        job.progress(progress.slices_done as u64, progress.total_slices as u64);
    })
    .map_err(|error| Error::engine(format!("PAR2 verification failed: {error}")))?;
    job.check()?;
    Ok(verification_json(&report))
}

/// Verify a PAR2 set and restore damaged or missing files into a new directory.
/// The original input tree is read only. The destination must not already exist.
pub fn recover_to_new_directory(
    index_path: &Path,
    source_dir: &Path,
    destination: &Path,
    job: &Job,
) -> Result<Value> {
    validate_index_and_set_size(index_path)?;
    validate_directory(source_dir, "Choose a regular source directory")?;
    validate_new_destination(destination)?;
    job.check()?;

    // Metadata parsing is bounded above, and all recovered files together are
    // capped before loading recovery blocks or allocating reconstructed data.
    let mut set = RecoverySet::load_metadata(index_path)
        .map_err(|error| Error::engine(format!("Could not read PAR2 recovery set: {error}")))?;
    validate_source_members(&set, source_dir)?;
    let expected_bytes = set.files.iter().try_fold(0u64, |sum, file| {
        sum.checked_add(file.length)
            .ok_or_else(|| Error::new(ErrorKind::Limit, "PAR2 file sizes overflow"))
    })?;
    if expected_bytes > MAX_RECOVERED_BYTES {
        return Err(Error::new(
            ErrorKind::Limit,
            "This recovery route is limited to 512 MiB total source data",
        ));
    }
    let recovery_bytes = set.recovery_index.values().try_fold(0u64, |sum, block| {
        sum.checked_add(block.len as u64)
            .ok_or_else(|| Error::new(ErrorKind::Limit, "PAR2 recovery size overflow"))
    })?;
    if recovery_bytes > MAX_PAR2_SET_BYTES {
        return Err(Error::new(
            ErrorKind::Limit,
            "PAR2 recovery data exceeds the 512 MiB memory budget",
        ));
    }
    set.load_recovery_blocks(None)
        .map_err(|error| Error::engine(format!("Could not load PAR2 recovery data: {error}")))?;
    job.check()?;

    let report = verify::verify_with_progress(&set, source_dir, |progress| {
        job.progress(progress.slices_done as u64, progress.total_slices as u64);
    })
    .map_err(|error| Error::engine(format!("PAR2 verification failed: {error}")))?;
    job.check()?;
    if report.is_ok() {
        return Ok(json!({
            "schema_version": 1,
            "status": "already_valid",
            "files": [],
            "destination_created": false,
        }));
    }
    if !report.is_repairable() {
        return Err(Error::input(format!(
            "Recovery needs {} blocks, but only {} are available",
            report.total_bad_slices(), report.available_recovery_blocks
        )));
    }

    // Run repair in a private sibling staging directory first, so malformed
    // or incompatible PAR2 data cannot leave a partially populated destination.
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stage = tempfile::Builder::new()
        .prefix(".file-studio-par2-")
        .tempdir_in(parent)?;
    // The engine writes restored members beneath this directory. Create only
    // validated parent directories up front so nested names work without
    // allowing a recovery set to escape the staging root.
    for entry in &set.files {
        let staged_path = safe_recovery_path(stage.path(), &entry.name)?;
        if let Some(parent) = staged_path.parent() {
            fs::create_dir_all(parent)?;
        }
    }
    let plan = repair::repair(
        &set,
        &report,
        source_dir,
        &RepairOptions {
            out_dir: Some(stage.path().to_path_buf()),
            dry_run: false,
        },
    )
    .map_err(|error| Error::engine(format!("PAR2 recovery failed: {error}")))?;
    job.check()?;

    // Atomic create_dir rejects an existing path, including a dangling symlink.
    fs::create_dir(destination).map_err(|error| {
        Error::input(format!(
            "Could not create a new recovery destination (it may already exist): {error}"
        ))
    })?;
    let mut published = Vec::new();
    let publish_result = (|| -> Result<()> {
        for repaired in &plan.repaired_files {
            job.check()?;
            let source = safe_recovery_path(stage.path(), &repaired.name)?;
            let target = safe_recovery_path(destination, &repaired.name)?;
            copy_new_file(&source, &target, job)?;
            published.push(target);
        }
        Ok(())
    })();
    if let Err(error) = publish_result {
        for path in published {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir(destination);
        return Err(error);
    }

    Ok(json!({
        "schema_version": 1,
        "status": "recovered",
        "files": plan.repaired_files.iter().map(|file| json!({
            "name": file.name,
            "bytes": fs::metadata(destination.join(&file.name)).map(|m| m.len()).unwrap_or(0),
            "slices_repaired": file.slices_repaired,
            "verified": file.verified,
        })).collect::<Vec<_>>(),
        "destination": destination,
        "warning": "PAR2 verifies repaired blocks against the recovery-set checksums. The recovery set does not authenticate who created it.",
    }))
}

fn parse_recovery_percent(parameter: &str) -> Result<u8> {
    let value = if parameter.trim().is_empty() {
        10
    } else {
        parameter
            .trim()
            .parse::<u8>()
            .map_err(|_| Error::input("Recovery percentage must be an integer from 1 to 50"))?
    };
    if !(1..=50).contains(&value) {
        return Err(Error::input("Recovery percentage must be from 1 to 50"));
    }
    Ok(value)
}

fn validate_directory(path: &Path, message: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::input(message));
    }
    Ok(())
}

fn validate_index_and_set_size(index_path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(index_path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::input("Choose a regular, non-symlink .par2 index file"));
    }
    if !index_path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("par2"))
    {
        return Err(Error::input("Choose a .par2 index file"));
    }
    let parent = index_path.parent().unwrap_or_else(|| Path::new("."));
    let mut count = 0usize;
    let mut bytes = 0u64;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("par2")) {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(Error::input(
                    "PAR2 directories cannot contain symlinked or special .par2 entries",
                ));
            }
            count += 1;
            bytes = bytes
                .checked_add(metadata.len())
                .ok_or_else(|| Error::new(ErrorKind::Limit, "PAR2 set size overflow"))?;
            if count > MAX_PAR2_SET_FILES || bytes > MAX_PAR2_SET_BYTES {
                return Err(Error::new(
                    ErrorKind::Limit,
                    "PAR2 set is limited to 256 files and 512 MiB of recovery data",
                ));
            }
        }
    }
    Ok(())
}

fn validate_new_destination(path: &Path) -> Result<()> {
    if path.file_name().is_none() {
        return Err(Error::input("Choose a new recovery directory"));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::input("Recovery destination already exists; choose a new directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn safe_recovery_path(root: &Path, name: &str) -> Result<PathBuf> {
    let relative = Path::new(name);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            !matches!(component, std::path::Component::Normal(_))
        })
    {
        return Err(Error::input("PAR2 set contains an unsafe output path"));
    }
    Ok(root.join(relative))
}

fn validate_source_members(set: &RecoverySet, source_dir: &Path) -> Result<()> {
    for entry in &set.files {
        let relative = Path::new(&entry.name);
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(Error::input("PAR2 set contains an unsafe source path"));
        }
        let mut current = source_dir.to_path_buf();
        let components = relative.components().collect::<Vec<_>>();
        for (index, component) in components.iter().enumerate() {
            current.push(component.as_os_str());
            let metadata = match fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() {
                return Err(Error::input(
                    "PAR2 source members cannot traverse symbolic links",
                ));
            }
            if index + 1 == components.len() {
                if !metadata.is_file() {
                    return Err(Error::input(
                        "An existing PAR2 source member is not a regular file",
                    ));
                }
            } else if !metadata.is_dir() {
                return Err(Error::input("PAR2 source path contains a non-directory"));
            }
        }
    }
    Ok(())
}

fn copy_new_file(source: &Path, target: &Path, job: &Job) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::input("PAR2 engine produced a non-regular staged file"));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new().write(true).create_new(true).open(target)?;
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        job.check()?;
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
    }
    output.sync_all()?;
    Ok(())
}

fn verification_json(report: &verify::VerifyReport) -> Value {
    json!({
        "schema_version": 1,
        "valid": report.is_ok(),
        "repairable": report.is_repairable(),
        "bad_slices": report.total_bad_slices(),
        "available_recovery_blocks": report.available_recovery_blocks,
        "files": report.files.iter().map(|file| json!({
            "name": file.name,
            "status": match file.status {
                FileStatus::Ok => "ok",
                FileStatus::Damaged => "damaged",
                FileStatus::Missing => "missing",
            },
            "total_slices": file.total_slices,
            "bad_slices": file.bad_slices,
        })).collect::<Vec<_>>(),
        "warning": "PAR2 checksums detect data changes but do not authenticate the source or the recovery-set creator.",
    })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

    #[test]
    fn recovery_percentage_is_bounded() {
        assert_eq!(parse_recovery_percent("").unwrap(), 10);
        assert_eq!(parse_recovery_percent(" 25 ").unwrap(), 25);
        for invalid in ["0", "51", "-1", "1.5", "100", "abc"] {
            assert!(parse_recovery_percent(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn recovery_paths_reject_traversal_and_absolute_names() {
        let root = Path::new("restore");
        for name in ["../escape", "a/../../escape", "/absolute", "", "."] {
            assert!(safe_recovery_path(root, name).is_err(), "{name}");
        }
        assert_eq!(safe_recovery_path(root, "nested/file.bin").unwrap(), root.join("nested/file.bin"));
    }

    #[test]
    fn copy_never_overwrites_existing_recovery_output() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("stage.bin");
        let target = temp.path().join("existing.bin");
        fs::write(&source, b"verified recovery").unwrap();
        fs::write(&target, b"keep existing").unwrap();
        let result = copy_new_file(&source, &target, &Job::new());
        assert!(result.is_err());
        assert_eq!(fs::read(target).unwrap(), b"keep existing");
    }

    #[test]
    fn par2_set_detects_damage_and_restores_to_new_directory() {
        let root = tempfile::tempdir().unwrap();
        let source_dir = root.path().join("source");
        let set_dir = root.path().join("parity");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&set_dir).unwrap();
        let source = source_dir.join("sample.bin");
        let original = (0usize..2 * 1024 * 1024)
            .map(|index| (index.wrapping_mul(37) % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&source, &original).unwrap();

        let created = create_for_file(&source, &set_dir, "30", &Job::new()).unwrap();
        let index = PathBuf::from(created["index"].as_str().unwrap());
        assert!(index.is_file());
        assert!(verify_set(&index, &source_dir, &Job::new()).unwrap()["valid"].as_bool().unwrap());

        let mut damaged = OpenOptions::new().write(true).open(&source).unwrap();
        damaged.seek(SeekFrom::Start(32 * 1024)).unwrap();
        damaged.write_all(b"damaged!").unwrap();
        drop(damaged);
        let verification = verify_set(&index, &source_dir, &Job::new()).unwrap();
        assert!(!verification["valid"].as_bool().unwrap());
        assert!(verification["repairable"].as_bool().unwrap());

        let destination = root.path().join("restored");
        let recovered = recover_to_new_directory(
            &index,
            &source_dir,
            &destination,
            &Job::new(),
        )
        .unwrap();
        assert_eq!(recovered["status"], "recovered");
        assert_eq!(fs::read(destination.join("sample.bin")).unwrap(), original);
        assert_ne!(fs::read(&source).unwrap(), original);
        assert!(recover_to_new_directory(
            &index,
            &source_dir,
            &destination,
            &Job::new()
        )
        .is_err());
    }
}
