//! Bounded, copy-on-write GZIP file workflows.

use flate2::{read::MultiGzDecoder, write::GzEncoder, Compression};
use localwright_core::{write_new, Error, ErrorKind, Job, Result};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
    time::SystemTime,
};

const MAX_COMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 1024 * 1024 * 1024;
const BUFFER_SIZE: usize = 32 * 1024;

struct BoundedOutput<'a> {
    file: &'a mut File,
    written: u64,
}

impl Write for BoundedOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > MAX_COMPRESSED_BYTES.saturating_sub(self.written) {
            return Err(io::Error::other("GZIP output exceeds the 1 GiB limit"));
        }
        let count = self.file.write(bytes)?;
        self.written += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn open_regular(path: &Path, limit: u64) -> Result<(File, u64, Option<SystemTime>)> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Error::input("Choose a regular, non-symlink file"));
    }
    if before.len() > limit {
        return Err(Error::new(
            ErrorKind::Limit,
            "GZIP input exceeds the 1 GiB limit",
        ));
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    let before_modified = before.modified().ok();
    let opened_modified = opened.modified().ok();
    if !opened.is_file() || opened.len() != before.len() || before_modified != opened_modified {
        return Err(Error::input("GZIP input changed while it was being opened"));
    }
    Ok((file, opened.len(), opened_modified))
}

fn ensure_unchanged(
    file: &File,
    expected_size: u64,
    expected_modified: Option<SystemTime>,
) -> Result<()> {
    let metadata = file.metadata()?;
    if metadata.len() != expected_size
        || expected_modified.is_some_and(|expected| metadata.modified().ok() != Some(expected))
    {
        return Err(Error::input("GZIP input changed while it was being read"));
    }
    Ok(())
}

fn copy_limited(
    reader: &mut impl Read,
    writer: &mut impl Write,
    limit: u64,
    progress_total: Option<u64>,
    job: &Job,
) -> Result<u64> {
    let mut total = 0u64;
    let mut buffer = [0; BUFFER_SIZE];
    loop {
        job.check()?;
        let count = reader
            .read(&mut buffer)
            .map_err(|error| Error::input(format!("Invalid or corrupt GZIP stream: {error}")))?;
        if count == 0 {
            return Ok(total);
        }
        let count = count as u64;
        if count > limit.saturating_sub(total) {
            return Err(Error::new(
                ErrorKind::Limit,
                "GZIP expansion exceeds the 1 GiB limit",
            ));
        }
        writer.write_all(&buffer[..count as usize])?;
        total += count;
        if let Some(total_bytes) = progress_total {
            job.progress(total, total_bytes);
        }
    }
}

pub(super) fn create(input: &Path, output: &Path, job: &Job) -> Result<Value> {
    if !output
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
    {
        return Err(Error::input("Choose .gz output"));
    }
    let (mut source, source_bytes, modified) = open_regular(input, MAX_EXPANDED_BYTES)?;
    let mut output_bytes = 0u64;
    write_new(output, |file| {
        let mut bounded_output = BoundedOutput { file, written: 0 };
        let mut encoder = GzEncoder::new(&mut bounded_output, Compression::default());
        let copied = copy_limited(
            &mut source,
            &mut encoder,
            MAX_EXPANDED_BYTES,
            Some(source_bytes),
            job,
        )?;
        if copied != source_bytes {
            return Err(Error::input("Source changed while GZIP was being created"));
        }
        ensure_unchanged(&source, source_bytes, modified)?;
        let output = encoder
            .finish()
            .map_err(|error| Error::input(format!("Could not finish GZIP stream: {error}")))?;
        output.flush()?;
        output_bytes = output.written;
        job.check()
    })?;
    Ok(json!({
        "schema_version": 1,
        "format": "gzip",
        "source_bytes": source_bytes,
        "compressed_bytes": output_bytes,
        "compression_level": "default",
    }))
}

pub(super) fn extract(input: &Path, output: &Path, job: &Job) -> Result<Value> {
    let (source, compressed_bytes, modified) = open_regular(input, MAX_COMPRESSED_BYTES)?;
    let mut expanded_bytes = 0u64;
    write_new(output, |file| {
        let mut decoder = MultiGzDecoder::new(source);
        job.progress(0, 0);
        expanded_bytes = copy_limited(&mut decoder, file, MAX_EXPANDED_BYTES, None, job)?;
        ensure_unchanged(decoder.get_ref(), compressed_bytes, modified)?;
        job.check()
    })?;
    Ok(json!({
        "schema_version": 1,
        "format": "gzip",
        "compressed_bytes": compressed_bytes,
        "expanded_bytes": expanded_bytes,
    }))
}

pub(super) fn test(input: &Path, job: &Job) -> Result<Value> {
    let (source, compressed_bytes, modified) = open_regular(input, MAX_COMPRESSED_BYTES)?;
    let mut decoder = MultiGzDecoder::new(source);
    let expanded_bytes =
        copy_limited(&mut decoder, &mut io::sink(), MAX_EXPANDED_BYTES, None, job)?;
    ensure_unchanged(decoder.get_ref(), compressed_bytes, modified)?;
    Ok(json!({
        "schema_version": 1,
        "format": "gzip",
        "valid": true,
        "compressed_bytes": compressed_bytes,
        "expanded_bytes": expanded_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn compressed(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn create_extract_and_test_round_trip_without_overwriting() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("report.txt");
        let archive = directory.path().join("report.txt.gz");
        let output = directory.path().join("restored.txt");
        fs::write(&input, b"offline archive fixture\n").unwrap();

        let created = create(&input, &archive, &Job::new()).unwrap();
        assert_eq!(created["source_bytes"], 24);
        let checked = test(&archive, &Job::new()).unwrap();
        assert_eq!(checked["valid"], true);
        assert_eq!(checked["expanded_bytes"], 24);
        let extracted = extract(&archive, &output, &Job::new()).unwrap();
        assert_eq!(extracted["expanded_bytes"], 24);
        assert_eq!(fs::read(&output).unwrap(), b"offline archive fixture\n");
        assert_eq!(fs::read(&input).unwrap(), b"offline archive fixture\n");
        assert!(create(&input, &archive, &Job::new()).is_err());
        assert!(extract(&archive, &output, &Job::new()).is_err());
    }

    #[test]
    fn operations_are_registered_and_reach_the_native_processing_handler() {
        use localwright_core::Request;

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.txt");
        let archive = directory.path().join("input.txt.gz");
        let restored = directory.path().join("restored.txt");
        fs::write(&input, b"native operation route").unwrap();

        for id in ["gzip-create", "gzip-extract", "gzip-test"] {
            assert!(crate::OPERATIONS.iter().any(|operation| operation.id == id));
        }
        let created = crate::handle(
            Request {
                operation: "gzip-create".into(),
                input,
                output: archive.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(created.written, Some(archive.clone()));

        let checked = crate::handle(
            Request {
                operation: "gzip-test".into(),
                input: archive.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        let report: Value = serde_json::from_str(&checked.preview).unwrap();
        assert_eq!(report["valid"], true);

        let extracted = crate::handle(
            Request {
                operation: "gzip-extract".into(),
                input: archive,
                output: restored.clone(),
                ..Request::default()
            },
            Job::new(),
        )
        .unwrap();
        assert_eq!(extracted.written, Some(restored.clone()));
        assert_eq!(fs::read(restored).unwrap(), b"native operation route");
    }

    #[test]
    fn decoder_accepts_concatenated_members_and_checks_each_member() {
        let first = compressed(b"first ");
        let second = compressed(b"second");
        let mut bytes = first;
        bytes.extend(second);
        let mut decoder = MultiGzDecoder::new(Cursor::new(bytes));
        let mut output = Vec::new();
        let expanded = copy_limited(&mut decoder, &mut output, 32, None, &Job::new()).unwrap();
        assert_eq!(expanded, 12);
        assert_eq!(output, b"first second");
    }

    #[test]
    fn rejects_corrupt_crc_and_truncated_streams() {
        let mut corrupt = compressed(b"verified bytes");
        let trailer = corrupt.len() - 8;
        corrupt[trailer] ^= 0x80;
        let mut decoder = MultiGzDecoder::new(Cursor::new(corrupt));
        assert!(copy_limited(&mut decoder, &mut io::sink(), 64, None, &Job::new()).is_err());

        let mut truncated = compressed(b"verified bytes");
        truncated.truncate(truncated.len() - 3);
        let mut decoder = MultiGzDecoder::new(Cursor::new(truncated));
        assert!(copy_limited(&mut decoder, &mut io::sink(), 64, None, &Job::new()).is_err());
    }

    #[test]
    fn failed_extraction_does_not_publish_partial_output() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("corrupt.gz");
        let output = directory.path().join("partial.txt");
        let mut bytes = compressed(b"content must not be published");
        let trailer = bytes.len() - 8;
        bytes[trailer] ^= 1;
        fs::write(&input, bytes).unwrap();

        assert!(extract(&input, &output, &Job::new()).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn rejects_expansion_limit_and_bad_output_extension() {
        let mut decoder = MultiGzDecoder::new(Cursor::new(compressed(b"12345678")));
        let mut output = Vec::new();
        assert!(copy_limited(&mut decoder, &mut output, 7, None, &Job::new()).is_err());

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        let output = directory.path().join("output.zip");
        fs::write(&input, b"text").unwrap();
        assert!(create(&input, &output, &Job::new()).is_err());
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_source() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.txt");
        let link = directory.path().join("source.gz");
        let output = directory.path().join("output.gz");
        fs::write(&source, b"text").unwrap();
        symlink(&source, &link).unwrap();
        assert!(create(&link, &output, &Job::new()).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn cancelled_job_does_not_publish_output() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("source.txt");
        let output = directory.path().join("source.gz");
        fs::write(&input, vec![0u8; 256 * 1024]).unwrap();
        let job = Job::new();
        job.cancel();
        assert!(create(&input, &output, &job).is_err());
        assert!(!output.exists());
    }
}
