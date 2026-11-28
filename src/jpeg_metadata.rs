use localwright_core::{read_bounded, write_new, Error, ErrorKind, Job, Result};
use serde_json::{json, Value};
use std::{fs, io::Write, path::Path};

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const XMP_ID: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";

/// Inspect JPEG metadata-bearing APP segments, or remove the supported classes
/// into a new file. This deliberately does not decode image data.
pub fn process(input: &Path, output: Option<&Path>, job: &Job) -> Result<Value> {
    if output.is_some_and(|p| {
        !p.extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("jpg") || x.eq_ignore_ascii_case("jpeg"))
    }) {
        return Err(Error::input("Choose .jpg or .jpeg output"));
    }
    let before = fs::symlink_metadata(input)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Error::input("Expected a regular non-symlink JPEG file"));
    }
    let bytes = read_bounded(input, MAX_BYTES)?;
    let segments = parse(&bytes, job)?;
    let mut exif = 0usize;
    let mut xmp = 0usize;
    let mut photoshop = 0usize;
    for segment in &segments {
        match segment.kind {
            Kind::Exif => exif += 1,
            Kind::Xmp => xmp += 1,
            Kind::Photoshop => photoshop += 1,
            Kind::Other => {}
            Kind::Tail => {}
        }
    }
    let removed = exif + xmp + photoshop;
    if let Some(output) = output {
        let after = fs::symlink_metadata(input)?;
        if after.len() != before.len() || after.modified()? != before.modified()? {
            return Err(Error::input("JPEG changed during metadata inspection"));
        }
        job.check()?;
        write_new(output, |file| {
            file.write_all(&bytes[..2])?;
            for s in &segments {
                job.check()?;
                if s.kind == Kind::Other || s.kind == Kind::Tail {
                    file.write_all(s.bytes)?;
                }
            }
            job.check()
        })?;
        Ok(
            json!({"schema_version":1,"removed":{"exif_app1":exif,"xmp_app1":xmp,"photoshop_iptc_app13":photoshop},"retained_app_segments":segments.iter().filter(|s| s.kind == Kind::Other).count()}),
        )
    } else {
        Ok(
            json!({"schema_version":1,"segments":{"exif_app1":exif,"xmp_app1":xmp,"photoshop_iptc_app13":photoshop,"other_app_segments":segments.iter().filter(|s| s.kind == Kind::Other).count()},"removable":removed}),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Exif,
    Xmp,
    Photoshop,
    Other,
    Tail,
}
struct Segment<'a> {
    kind: Kind,
    bytes: &'a [u8],
}

fn parse<'a>(bytes: &'a [u8], job: &Job) -> Result<Vec<Segment<'a>>> {
    if !bytes.starts_with(&[0xff, 0xd8]) {
        return Err(Error::input("Expected JPEG SOI signature"));
    }
    let mut pos = 2usize;
    let mut result = Vec::new();
    loop {
        job.check()?;
        if pos >= bytes.len() || bytes[pos] != 0xff {
            return Err(Error::input(
                "Malformed JPEG marker sequence before scan data",
            ));
        }
        let start = pos;
        while bytes.get(pos) == Some(&0xff) {
            pos += 1;
        }
        let marker = *bytes
            .get(pos)
            .ok_or_else(|| Error::input("Truncated JPEG marker"))?;
        pos += 1;
        if marker == 0x00 {
            return Err(Error::input(
                "Unexpected stuffed byte before JPEG scan data",
            ));
        }
        if marker == 0xda {
            // SOS: keep the scan header and all compressed data untouched.
            let len_bytes = bytes
                .get(pos..pos + 2)
                .ok_or_else(|| Error::input("Truncated JPEG scan header"))?;
            let length = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
            if length < 2
                || pos
                    .checked_add(length)
                    .filter(|end| *end <= bytes.len())
                    .is_none()
            {
                return Err(Error::input("Invalid JPEG scan header length"));
            }
            check_segment_limit(result.len())?;
            result.push(Segment {
                kind: Kind::Tail,
                bytes: &bytes[start..],
            });
            break;
        }
        if marker == 0xd9 {
            // EOI before scan is not a usable image for this operation.
            return Err(Error::input("JPEG has no scan data"));
        }
        // SOI, TEM and restart markers carry no length. A nested SOI is invalid.
        if marker == 0xd8 {
            return Err(Error::input("Unexpected nested JPEG SOI marker"));
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            check_segment_limit(result.len())?;
            result.push(Segment {
                kind: Kind::Other,
                bytes: &bytes[start..pos],
            });
            continue;
        }
        let len_bytes = bytes
            .get(pos..pos + 2)
            .ok_or_else(|| Error::input("Truncated JPEG segment length"))?;
        let length = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        if length < 2 {
            return Err(Error::input("Invalid JPEG segment length"));
        }
        let end = pos
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| Error::input("Truncated JPEG segment"))?;
        let payload = &bytes[pos + 2..end];
        let kind = if marker == 0xe1 && payload.starts_with(b"Exif\0\0") {
            Kind::Exif
        } else if marker == 0xe1 && payload.starts_with(XMP_ID) {
            Kind::Xmp
        } else if marker == 0xed && payload.starts_with(b"Photoshop 3.0\0") {
            Kind::Photoshop
        } else {
            Kind::Other
        };
        check_segment_limit(result.len())?;
        result.push(Segment {
            kind,
            bytes: &bytes[start..end],
        });
        pos = end;
    }
    Ok(result)
}

fn check_segment_limit(count: usize) -> Result<()> {
    if count >= 4096 {
        Err(Error::new(
            ErrorKind::Limit,
            "JPEG header segment limit exceeded",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let n = (payload.len() + 2) as u16;
        [
            vec![0xff, marker],
            n.to_be_bytes().to_vec(),
            payload.to_vec(),
        ]
        .concat()
    }
    fn fixture() -> Vec<u8> {
        let mut b = vec![0xff, 0xd8];
        b.extend(seg(0xe1, b"Exif\0\0camera"));
        b.extend(seg(0xe1, b"http://ns.adobe.com/xap/1.0/\0xmp"));
        b.extend(seg(0xed, b"Photoshop 3.0\0iptc"));
        b.extend(seg(0xe2, b"ICC_PROFILE\0color"));
        b.extend(seg(0xda, b"scan-header"));
        b.extend([0x12, 0xff, 0, 0x34, 0xff, 0xd9]);
        b
    }
    #[test]
    fn strips_supported_jpeg_metadata_copy_on_write_and_preserves_scan_and_icc() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.jpg");
        let output = dir.path().join("out.jpg");
        let original = fixture();
        fs::write(&input, &original).unwrap();
        let report = process(&input, Some(&output), &Job::new()).unwrap();
        assert_eq!(report["removed"]["exif_app1"], 1);
        assert_eq!(report["removed"]["xmp_app1"], 1);
        assert_eq!(report["removed"]["photoshop_iptc_app13"], 1);
        let cleaned = fs::read(&output).unwrap();
        assert!(cleaned.windows(11).any(|w| w == b"ICC_PROFILE"));
        assert!(cleaned.ends_with(&[0x12, 0xff, 0, 0x34, 0xff, 0xd9]));
        assert_eq!(fs::read(input).unwrap(), original);
        assert!(process(&dir.path().join("in.jpg"), Some(&output), &Job::new()).is_err());
    }
    #[test]
    fn refuses_malformed_segments_without_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("bad.jpg");
        let out = dir.path().join("out.jpg");
        fs::write(&input, [0xff, 0xd8, 0xff, 0xe1, 0, 30, 1]).unwrap();
        assert!(process(&input, Some(&out), &Job::new()).is_err());
        assert!(!out.exists());
    }
}
