use exif::Reader;
use localwright_core::{read_bounded, Error, Job, Result};
use serde_json::{json, Value};
use std::{
    fmt::{self, Write as FmtWrite},
    fs,
    io::{BufReader, Cursor},
    path::Path,
};

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FIELDS: usize = 512;
const MAX_VALUE_BYTES: usize = 1024;

/// Read bounded EXIF fields from formats handled by kamadak-exif.
pub fn inspect(path: &Path, job: &Job) -> Result<Value> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Error::input("Expected a regular non-symlink image file"));
    }
    if before.len() > MAX_BYTES {
        return Err(Error::input(
            "Image exceeds the 32 MiB EXIF inspection limit",
        ));
    }
    job.check()?;
    let bytes = read_bounded(path, MAX_BYTES)?;
    let after_read = fs::symlink_metadata(path)?;
    if !after_read.is_file()
        || after_read.file_type().is_symlink()
        || after_read.len() != before.len()
        || after_read.modified()? != before.modified()?
    {
        return Err(Error::input("Image changed during EXIF inspection"));
    }
    let exif = Reader::new()
        .read_from_container(&mut BufReader::new(Cursor::new(bytes)))
        .map_err(|error| Error::input(format!("EXIF inspection failed: {error}")))?;
    job.check()?;
    let total = exif.fields().len();
    let mut fields = Vec::with_capacity(total.min(MAX_FIELDS));
    for field in exif.fields().take(MAX_FIELDS) {
        job.check()?;
        let mut value = BoundedText::new(MAX_VALUE_BYTES);
        let _ = fmt::write(
            &mut value,
            format_args!("{}", field.display_value().with_unit(&exif)),
        );
        if value.truncated {
            value.text.push_str("…[truncated]");
        }
        fields.push(json!({
            "tag": field.tag.to_string(),
            "ifd": field.ifd_num.to_string(),
            "value": value.text,
        }));
    }
    let after = fs::symlink_metadata(path)?;
    if after.len() != before.len() || after.modified()? != before.modified()? {
        return Err(Error::input("Image changed during EXIF inspection"));
    }
    Ok(json!({
        "schema_version": 1,
        "parser": "kamadak-exif",
        "supported_container_families": ["JPEG", "TIFF", "HEIF/HEIC/AVIF", "PNG", "WebP"],
        "field_count": total,
        "fields": fields,
        "truncated": total > MAX_FIELDS,
        "limits": {"input_bytes": MAX_BYTES, "fields": MAX_FIELDS, "value_bytes": MAX_VALUE_BYTES},
    }))
}

struct BoundedText {
    text: String,
    limit: usize,
    truncated: bool,
}

impl BoundedText {
    fn new(limit: usize) -> Self {
        Self {
            text: String::with_capacity(limit),
            limit,
            truncated: false,
        }
    }
}

impl FmtWrite for BoundedText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = self.limit.saturating_sub(self.text.len());
        if value.len() <= remaining {
            self.text.push_str(value);
            return Ok(());
        }
        let mut end = remaining.min(value.len());
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.text.push_str(&value[..end]);
        self.truncated = true;
        Err(fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn minimal_tiff_with_make() -> Vec<u8> {
        // Little-endian TIFF with one ASCII Make tag containing "ABC".
        [
            b"II".as_slice(),
            &42u16.to_le_bytes(),
            &8u32.to_le_bytes(),
            &1u16.to_le_bytes(),
            &0x010fu16.to_le_bytes(),
            &2u16.to_le_bytes(),
            &4u32.to_le_bytes(),
            b"ABC\0",
            &0u32.to_le_bytes(),
        ]
        .concat()
    }

    #[test]
    fn reads_bounded_tiff_exif_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("camera.tif");
        fs::write(&path, minimal_tiff_with_make()).unwrap();
        let report = inspect(&path, &Job::new()).unwrap();
        assert_eq!(report["field_count"], 1);
        assert_eq!(report["fields"][0]["tag"], "Make");
        assert_eq!(report["fields"][0]["value"], "\"ABC\"");
    }

    #[test]
    fn rejects_oversized_or_non_image_input() {
        let dir = tempfile::tempdir().unwrap();
        let text = dir.path().join("plain.txt");
        fs::write(&text, b"not an image").unwrap();
        assert!(inspect(&text, &Job::new()).is_err());
        let large = dir.path().join("large.tif");
        fs::File::create(&large)
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        assert!(inspect(&large, &Job::new())
            .unwrap_err()
            .message
            .contains("32 MiB"));
    }
}
