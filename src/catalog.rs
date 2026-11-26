use localwright_core::{read_bounded, Error, ErrorKind, Job, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};

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
    let query = parameter.trim();
    if query.is_empty() || query.len() > 4096 {
        return Err(Error::input("Enter a path search term up to 4 KiB"));
    }
    let inventory = load(catalog, job)?;
    let query = query.to_lowercase();
    let scanned = inventory.files.len();
    let mut matches = Vec::new();
    for entry in inventory.files {
        job.check()?;
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

fn load(catalog: &Path, job: &Job) -> Result<Inventory> {
    const MAX_ENTRIES: usize = 10_000;
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
    for entry in &inventory.files {
        job.check()?;
        if entry.path.is_empty() || entry.path.contains('\0') {
            return Err(Error::input("Invalid inventory path"));
        }
    }
    Ok(inventory)
}

pub fn compare(before: &Path, after: &Path, job: &Job) -> Result<Value> {
    let mut before = indexed(before, job)?;
    let after = indexed(after, job)?;
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = 0;
    for (path, bytes) in after {
        job.check()?;
        match before.remove(&path) {
            None => added.push(json!({"path": path, "bytes": bytes})),
            Some(old) if old != bytes => {
                changed.push(json!({"path": path, "before_bytes": old, "after_bytes": bytes}))
            }
            Some(_) => unchanged += 1,
        }
    }
    let removed = before
        .into_iter()
        .map(|(path, bytes)| json!({"path": path, "bytes": bytes}))
        .collect::<Vec<_>>();
    Ok(
        json!({"schema_version": 1, "added": added, "removed": removed, "size_changed": changed, "same_size": unchanged}),
    )
}

fn indexed(path: &Path, job: &Job) -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    for entry in load(path, job)?.files {
        job.check()?;
        if result.insert(entry.path, entry.bytes).is_some() {
            return Err(Error::input("Duplicate path in saved inventory"));
        }
    }
    Ok(result)
}
