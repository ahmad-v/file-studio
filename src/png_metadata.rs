use localwright_core::{read_bounded, write_new, Error, ErrorKind, Job, Result};
use serde_json::{json, Value};
use std::{collections::BTreeMap, io::Write, path::Path};

const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CHUNKS: usize = 8192;
const REMOVABLE: [&str; 4] = ["tEXt", "zTXt", "iTXt", "eXIf"];

pub fn process(input: &Path, output: Option<&Path>, job: &Job) -> Result<Value> {
    if output.is_some_and(|path| {
        !path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("png"))
    }) {
        return Err(Error::input("Choose .png output"));
    }
    let bytes = read_bounded(input, MAX_BYTES)?;
    let chunks = parse(&bytes, job)?;
    let mut before = BTreeMap::<&str, usize>::new();
    let mut after = BTreeMap::<&str, usize>::new();
    for &(kind, _) in &chunks {
        *before.entry(kind).or_default() += 1;
        if !REMOVABLE.contains(&kind) {
            *after.entry(kind).or_default() += 1;
        }
    }
    let removable: usize = REMOVABLE
        .iter()
        .map(|kind| before.get(kind).copied().unwrap_or(0))
        .sum();
    if let Some(output) = output {
        job.check()?;
        write_new(output, |file| {
            file.write_all(SIGNATURE)?;
            for (kind, chunk) in chunks {
                job.check()?;
                if !REMOVABLE.contains(&kind) {
                    file.write_all(chunk)?;
                }
            }
            job.check()
        })?;
        Ok(json!({"schema_version": 1, "before": before, "after": after, "removed": removable}))
    } else {
        Ok(json!({"schema_version": 1, "chunks": before, "removable": removable}))
    }
}

fn parse<'a>(bytes: &'a [u8], job: &Job) -> Result<Vec<(&'a str, &'a [u8])>> {
    let mut rest = bytes
        .strip_prefix(SIGNATURE)
        .ok_or_else(|| Error::input("Expected PNG signature"))?;
    let mut chunks = Vec::new();
    let mut has_data = false;
    while !rest.is_empty() {
        job.check()?;
        if chunks.len() == MAX_CHUNKS {
            return Err(Error::new(ErrorKind::Limit, "PNG chunk limit exceeded"));
        }
        let (length, kind, chunk) = frame(rest)?;
        let payload_end = length + 8;
        let stored = u32::from_be_bytes(chunk[payload_end..].try_into().unwrap());
        if crc32fast::hash(&chunk[4..payload_end]) != stored {
            return Err(Error::input(format!("PNG {kind} chunk checksum mismatch")));
        }
        if chunks.is_empty() {
            if kind != "IHDR" || length != 13 {
                return Err(Error::input("PNG must start with a 13-byte IHDR chunk"));
            }
            for dimension in chunk[8..16].chunks_exact(4) {
                let value = u32::from_be_bytes(dimension.try_into().unwrap());
                if value == 0 || value > i32::MAX as u32 {
                    return Err(Error::input("Invalid PNG dimensions"));
                }
            }
        } else if kind == "IHDR" {
            return Err(Error::input("PNG contains a repeated IHDR chunk"));
        }
        has_data |= kind == "IDAT";
        chunks.push((kind, chunk));
        rest = &rest[chunk.len()..];
        if kind == "IEND" {
            if length != 0 || !rest.is_empty() || !has_data {
                return Err(Error::input("Invalid PNG image data or end chunk"));
            }
            return Ok(chunks);
        }
    }
    Err(Error::input("Missing PNG end chunk"))
}

fn frame(bytes: &[u8]) -> Result<(usize, &str, &[u8])> {
    let header = bytes
        .get(..8)
        .ok_or_else(|| Error::input("Incomplete PNG chunk header"))?;
    let length = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    let total = length
        .checked_add(12)
        .ok_or_else(|| Error::input("PNG chunk length overflow"))?;
    let chunk = bytes
        .get(..total)
        .ok_or_else(|| Error::input("Truncated PNG chunk"))?;
    let kind = &header[4..];
    if !kind.iter().all(u8::is_ascii_alphabetic) || !kind[2].is_ascii_uppercase() {
        return Err(Error::input("Invalid PNG chunk type"));
    }
    Ok((length, std::str::from_utf8(kind).unwrap(), chunk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn strips_only_supported_chunks_and_refuses_bad_crc_or_output_collision() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.png");
        let output = dir.path().join("output.png");
        let original = include_bytes!("../tests/fixtures/png-metadata.png");
        fs::write(&input, original).unwrap();
        let job = Job::new();
        let report = process(&input, Some(&output), &job).unwrap();
        assert_eq!(report["removed"], 4);
        assert_eq!(report["after"], json!({"IHDR": 1, "IDAT": 1, "IEND": 1}));
        assert_eq!(process(&output, None, &job).unwrap()["removable"], 0);
        assert_eq!(fs::read(&input).unwrap(), original);
        assert!(process(&input, Some(&output), &job).is_err());

        let corrupt = dir.path().join("corrupt.png");
        let refused = dir.path().join("refused.png");
        let mut damaged = original.to_vec();
        damaged[29] ^= 1;
        fs::write(&corrupt, damaged).unwrap();
        let error = process(&corrupt, Some(&refused), &job).unwrap_err();
        assert!(error.message.contains("checksum"));
        assert!(!refused.exists());
    }
}
