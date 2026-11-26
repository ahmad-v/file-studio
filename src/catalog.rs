use localwright_core::{read_bounded, Error, ErrorKind, Job, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema_version: u32,
    files: Vec<Entry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    bytes: u64,
}

pub fn search(catalog: &Path, parameter: &str, job: &Job) -> Result<Value> {
    const MAX_ENTRIES: usize = 10_000;
    let query = parameter.trim();
    if query.is_empty() || query.len() > 4096 {
        return Err(Error::input("Enter a path search term up to 4 KiB"));
    }
    let bytes = read_bounded(catalog, 16 * 1024 * 1024)?;
    job.check()?;
    let inventory: Inventory = serde_json::from_slice(&bytes)?;
    if inventory.schema_version != 1 {
        return Err(Error::input("Unsupported inventory version"));
    }
    if inventory.files.len() > MAX_ENTRIES {
        return Err(Error::new(
            ErrorKind::Limit,
            "Inventory exceeds 10,000 files",
        ));
    }
    let query = query.to_lowercase();
    let scanned = inventory.files.len();
    let mut matches = Vec::new();
    for entry in inventory.files {
        job.check()?;
        if entry.path.is_empty() || entry.path.contains('\0') {
            return Err(Error::input("Invalid inventory path"));
        }
        if entry.path.to_lowercase().contains(&query) {
            matches.push(entry);
        }
    }
    Ok(json!({
        "schema_version": 1,
        "catalogued_files": scanned,
        "matched_files": matches.len(),
        "files": matches,
    }))
}
