use localwright_core::{read_bounded, write_new, Error, ErrorKind, Job, Result};
use rusqlite::{config::DbConfig, limits::Limit, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs, io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const CATALOG_APPLICATION_ID: i64 = 0x4c57_5243;
const CATALOG_SCHEMA_VERSION: i64 = 2;
const MAX_CATALOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PATH_BYTES: i32 = 64 * 1024;

fn sqlite_error(error: rusqlite::Error) -> Error {
    Error::input(format!("Catalogue database error: {error}"))
}

fn is_sqlite_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("sqlite") || extension.eq_ignore_ascii_case("sqlite3")
        })
}

fn configure(db: &Connection) -> Result<()> {
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(sqlite_error)?;
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
        .map_err(sqlite_error)?;
    db.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_PATH_BYTES)
        .map_err(sqlite_error)?;
    db.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 4096)
        .map_err(sqlite_error)?;
    db.set_limit(Limit::SQLITE_LIMIT_COLUMN, 16)
        .map_err(sqlite_error)?;
    db.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
        .map_err(sqlite_error)?;
    Ok(())
}

fn open_catalog(path: &Path, writable: bool) -> Result<Connection> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::input("Choose a regular, non-symlink catalogue file"));
    }
    if metadata.len() > MAX_CATALOG_BYTES {
        return Err(Error::new(
            ErrorKind::Limit,
            "Catalogue database exceeds 64 MiB",
        ));
    }
    // macOS commonly exposes temporary directories through a symlinked parent
    // such as /var -> /private/var. SQLite NOFOLLOW applies to the path walk as
    // well as the final component, so pass it the canonical validated path.
    let canonical_path = fs::canonicalize(path)?;
    let canonical_metadata = fs::symlink_metadata(&canonical_path)?;
    if !canonical_metadata.is_file() || canonical_metadata.file_type().is_symlink() {
        return Err(Error::input("Choose a regular, non-symlink catalogue file"));
    }
    if canonical_metadata.len() > MAX_CATALOG_BYTES {
        return Err(Error::new(
            ErrorKind::Limit,
            "Catalogue database exceeds 64 MiB",
        ));
    }
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
    };
    let db = Connection::open_with_flags(canonical_path, flags).map_err(sqlite_error)?;
    configure(&db)?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;")
        .map_err(sqlite_error)?;
    if !writable {
        db.execute_batch("PRAGMA query_only=ON;")
            .map_err(sqlite_error)?;
    }
    let application_id: i64 = db
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let page_size: i64 = db
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if application_id != CATALOG_APPLICATION_ID
        || !(1..=CATALOG_SCHEMA_VERSION).contains(&version)
        || page_size != 4096
    {
        return Err(Error::input(
            "Unsupported or non-File-Studio catalogue database",
        ));
    }
    if writable && version == 1 {
        // Schema v1 did not store source identity. Preserve its history and mark
        // those rows unknown so the first refresh safely establishes a baseline.
        db.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE scans ADD COLUMN source_id TEXT;
             ALTER TABLE scans ADD COLUMN comparison_mode TEXT NOT NULL DEFAULT 'unknown';
             ALTER TABLE scans ADD COLUMN added_count INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE scans ADD COLUMN changed_count INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE scans ADD COLUMN removed_count INTEGER NOT NULL DEFAULT 0;
             PRAGMA user_version=2;
             COMMIT;",
        )
        .map_err(sqlite_error)?;
    }
    Ok(db)
}

/// Filesystem device and root-directory identity avoid treating the current
/// mount path as identity. Platforms without stable standard-library metadata
/// identifiers use a full-rescan fallback.
pub(super) fn stable_source_identity(root: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(root)
            .ok()
            .map(|metadata| format!("unix-dev:{}-ino:{}", metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        match file_id::get_low_res_file_id(root).ok()? {
            file_id::FileId::LowRes {
                volume_serial_number,
                file_index,
            } => Some(format!(
                "windows-volume:{volume_serial_number}-file:{file_index}"
            )),
            _ => None,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = root;
        None
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Delta {
    mode: &'static str,
    added: usize,
    changed: usize,
    removed: usize,
}

fn reconcile(
    previous_id: Option<&str>,
    current_id: Option<&str>,
    before: &[Entry],
    after: &[Entry],
) -> Delta {
    if previous_id.is_none() || current_id.is_none() || previous_id != current_id {
        return Delta {
            mode: "full-rescan",
            ..Delta::default()
        };
    }
    let old = before
        .iter()
        .map(|entry| (entry.path.as_str(), entry.bytes))
        .collect::<BTreeMap<_, _>>();
    let new = after
        .iter()
        .map(|entry| (entry.path.as_str(), entry.bytes))
        .collect::<BTreeMap<_, _>>();
    let added = new.keys().filter(|path| !old.contains_key(**path)).count();
    let removed = old.keys().filter(|path| !new.contains_key(**path)).count();
    let changed = new
        .iter()
        .filter(|(path, bytes)| old.get(**path).is_some_and(|old_bytes| old_bytes != *bytes))
        .count();
    Delta {
        mode: "same-source",
        added,
        changed,
        removed,
    }
}

fn scanned_unix_ms() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::input(format!("System clock precedes Unix epoch: {error}")))?;
    i64::try_from(now.as_millis()).map_err(|_| Error::input("System timestamp is out of range"))
}

fn root_label(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("directory")
        .chars()
        .take(255)
        .collect()
}

fn insert_scan(
    db: &mut Connection,
    label: &str,
    source_id: Option<&str>,
    delta: &Delta,
    files: &[Value],
    job: &Job,
) -> Result<i64> {
    if files.len() > 10_000 {
        return Err(Error::new(ErrorKind::Limit, "Scan exceeds 10,000 files"));
    }
    let scanned_at = scanned_unix_ms()?;
    let transaction = db.transaction().map_err(sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO scans(scanned_unix_ms, root_label, file_count, total_bytes, source_id, comparison_mode, added_count, changed_count, removed_count) VALUES(?1, ?2, 0, '0', ?3, ?4, ?5, ?6, ?7)",
            (scanned_at, label, source_id, delta.mode, delta.added as i64, delta.changed as i64, delta.removed as i64),
        )
        .map_err(sqlite_error)?;
    let scan_id = transaction.last_insert_rowid();
    let mut total_bytes = 0u128;
    {
        let mut insert = transaction
            .prepare("INSERT INTO files(scan_id, path, bytes) VALUES(?1, ?2, ?3)")
            .map_err(sqlite_error)?;
        let total = u64::try_from(files.len())
            .map_err(|_| Error::input("Catalogue row count is out of range"))?;
        for (index, file) in files.iter().enumerate() {
            job.check()?;
            let relative = file["path"]
                .as_str()
                .ok_or_else(|| Error::input("Scan report contains an invalid path"))?;
            let bytes = file["bytes"]
                .as_u64()
                .ok_or_else(|| Error::input("Scan report contains an invalid file size"))?;
            insert
                .execute((scan_id, relative, bytes.to_string()))
                .map_err(sqlite_error)?;
            let completed = u64::try_from(index + 1)
                .map_err(|_| Error::input("Catalogue progress is out of range"))?;
            job.progress(completed, total);
            total_bytes += u128::from(bytes);
        }
    }
    transaction
        .execute(
            "UPDATE scans SET file_count=?1, total_bytes=?2 WHERE id=?3",
            (files.len() as i64, total_bytes.to_string(), scan_id),
        )
        .map_err(sqlite_error)?;
    transaction.commit().map_err(sqlite_error)?;
    if files.is_empty() {
        job.progress(1, 1);
    }
    Ok(scan_id)
}

fn snapshot(db: &Connection, scan_id: i64, job: &Job) -> Result<Vec<Entry>> {
    let mut statement = db
        .prepare("SELECT path, bytes FROM files WHERE scan_id=?1 ORDER BY path")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_error)?;
    let mut files = Vec::new();
    for row in rows {
        job.check()?;
        let (path, bytes) = row.map_err(sqlite_error)?;
        let bytes = bytes
            .parse::<u64>()
            .map_err(|_| Error::input("Catalogue contains an invalid file size"))?;
        if path.is_empty() || path.contains('\0') {
            return Err(Error::input("Catalogue contains an invalid path"));
        }
        files.push(Entry { path, bytes });
        if files.len() > 10_000 {
            return Err(Error::new(
                ErrorKind::Limit,
                "Catalogue scan exceeds 10,000 files",
            ));
        }
    }
    Ok(files)
}

fn latest_scan(db: &Connection, job: &Job) -> Result<(i64, Vec<Entry>)> {
    let scan_id = db
        .query_row("SELECT id FROM scans ORDER BY id DESC LIMIT 1", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(sqlite_error)?;
    Ok((scan_id, snapshot(db, scan_id, job)?))
}

pub fn create(root: &Path, files: &[Value], output: &Path, job: &Job) -> Result<Value> {
    let root = fs::canonicalize(root)?;
    ensure_catalog_outside_root(&root, output)?;
    let temporary = tempfile::tempdir()?;
    let database_path = temporary.path().join("catalogue.sqlite");
    let mut db = Connection::open(&database_path).map_err(sqlite_error)?;
    configure(&db)?;
    db.execute_batch(&format!(
        "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA page_size=4096; PRAGMA max_page_count={}; PRAGMA application_id={}; PRAGMA user_version={};
         CREATE TABLE scans(id INTEGER PRIMARY KEY, scanned_unix_ms INTEGER NOT NULL, root_label TEXT NOT NULL, file_count INTEGER NOT NULL, total_bytes TEXT NOT NULL, source_id TEXT, comparison_mode TEXT NOT NULL, added_count INTEGER NOT NULL, changed_count INTEGER NOT NULL, removed_count INTEGER NOT NULL);
         CREATE TABLE files(scan_id INTEGER NOT NULL REFERENCES scans(id), path TEXT NOT NULL, bytes TEXT NOT NULL, PRIMARY KEY(scan_id,path)) WITHOUT ROWID;
         CREATE INDEX files_path ON files(path);",
        MAX_CATALOG_BYTES / 4096,
        CATALOG_APPLICATION_ID,
        CATALOG_SCHEMA_VERSION,
    ))
    .map_err(sqlite_error)?;
    let baseline = Delta {
        mode: "baseline",
        ..Delta::default()
    };
    let scan_id = insert_scan(
        &mut db,
        &root_label(&root),
        stable_source_identity(&root).as_deref(),
        &baseline,
        files,
        job,
    )?;
    db.close().map_err(|(_, error)| sqlite_error(error))?;

    let mut source = fs::File::open(&database_path)?;
    write_new(output, |destination| {
        let written = io::copy(&mut source, destination)?;
        if written > MAX_CATALOG_BYTES {
            return Err(Error::new(
                ErrorKind::Limit,
                "Catalogue output exceeds 64 MiB",
            ));
        }
        Ok(())
    })?;
    Ok(json!({
        "schema_version": CATALOG_SCHEMA_VERSION,
        "scan_id": scan_id,
        "files": files.len(),
        "database_bytes_limit": MAX_CATALOG_BYTES,
    }))
}

fn ensure_catalog_outside_root(root: &Path, catalog: &Path) -> Result<()> {
    let parent = catalog
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    if parent.starts_with(root) {
        return Err(Error::input(
            "Keep the catalogue outside the directory being scanned",
        ));
    }
    Ok(())
}

pub fn refresh(path: &Path, root: &Path, files: &[Value], job: &Job) -> Result<Value> {
    let root = fs::canonicalize(root)?;
    ensure_catalog_outside_root(&root, path)?;
    let mut db = open_catalog(path, true)?;
    db.execute_batch(&format!(
        "PRAGMA max_page_count={};",
        MAX_CATALOG_BYTES / 4096
    ))
    .map_err(sqlite_error)?;
    let previous_id: Option<String> = db
        .query_row(
            "SELECT source_id FROM scans ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .flatten();
    let previous = latest_scan(&db, job)?.1;
    let source_id = stable_source_identity(&root);
    let current = files
        .iter()
        .map(|file| {
            Ok(Entry {
                path: file["path"]
                    .as_str()
                    .ok_or_else(|| Error::input("Scan report contains an invalid path"))?
                    .to_owned(),
                bytes: file["bytes"]
                    .as_u64()
                    .ok_or_else(|| Error::input("Scan report contains an invalid file size"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let delta = reconcile(
        previous_id.as_deref(),
        source_id.as_deref(),
        &previous,
        &current,
    );
    let transaction_will_add_history = insert_scan(
        &mut db,
        &root_label(&root),
        source_id.as_deref(),
        &delta,
        files,
        job,
    )?;
    let report = db
        .query_row(
            "SELECT scanned_unix_ms, file_count, total_bytes FROM scans WHERE id=?1",
            [transaction_will_add_history],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    Ok(json!({
        "schema_version": CATALOG_SCHEMA_VERSION,
        "scan_id": transaction_will_add_history,
        "scanned_unix_ms": report.0,
        "files": report.1,
        "total_bytes": report.2,
        "comparison_mode": delta.mode,
        "added": delta.added,
        "changed": delta.changed,
        "removed": delta.removed,
        "history": true,
    }))
}

pub fn history(path: &Path, job: &Job) -> Result<Value> {
    let db = open_catalog(path, false)?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let sql = if version >= 2 {
        "SELECT id, scanned_unix_ms, root_label, file_count, total_bytes, comparison_mode, added_count, changed_count, removed_count FROM scans ORDER BY id DESC LIMIT 101"
    } else {
        "SELECT id, scanned_unix_ms, root_label, file_count, total_bytes, 'unknown', 0, 0, 0 FROM scans ORDER BY id DESC LIMIT 101"
    };
    let mut statement = db.prepare(sql).map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok(json!({
                "scan_id": row.get::<_, i64>(0)?,
                "scanned_unix_ms": row.get::<_, i64>(1)?,
                "root_label": row.get::<_, String>(2)?,
                "files": row.get::<_, i64>(3)?,
                "total_bytes": row.get::<_, String>(4)?,
                "comparison_mode": row.get::<_, String>(5)?,
                "added": row.get::<_, i64>(6)?,
                "changed": row.get::<_, i64>(7)?,
                "removed": row.get::<_, i64>(8)?,
            }))
        })
        .map_err(sqlite_error)?;
    let mut scans = Vec::new();
    for row in rows {
        job.check()?;
        scans.push(row.map_err(sqlite_error)?);
    }
    let truncated = scans.len() > 100;
    scans.truncate(100);
    Ok(json!({ "schema_version": CATALOG_SCHEMA_VERSION, "scans": scans, "truncated": truncated }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotComparisonRequest {
    before_scan_id: i64,
    after_scan_id: i64,
}

/// Compare two retained catalogue snapshots without touching the source volume.
/// The result reports whether the snapshots share a stable source identity so
/// callers can distinguish path deltas from comparisons across unrelated media.
pub fn compare_snapshots(catalog: &Path, parameter: &str, job: &Job) -> Result<Value> {
    if parameter.len() > 4096 {
        return Err(Error::new(
            ErrorKind::Limit,
            "Comparison options exceed 4 KiB",
        ));
    }
    let request: SnapshotComparisonRequest = serde_json::from_str(parameter)?;
    if request.before_scan_id < 1
        || request.after_scan_id < 1
        || request.before_scan_id == request.after_scan_id
    {
        return Err(Error::input("Choose two different positive scan IDs"));
    }
    let db = open_catalog(catalog, false)?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let query = if version >= 2 {
        "SELECT source_id, root_label, scanned_unix_ms FROM scans WHERE id=?1"
    } else {
        "SELECT NULL, root_label, scanned_unix_ms FROM scans WHERE id=?1"
    };
    let read_scan = |scan_id: i64| -> Result<(Option<String>, String, i64)> {
        db.query_row(query, [scan_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| Error::input(format!("Catalogue scan {scan_id} does not exist")))
    };
    let (before_source, before_label, before_time) = read_scan(request.before_scan_id)?;
    let (after_source, after_label, after_time) = read_scan(request.after_scan_id)?;
    let before = indexed_scan(&db, request.before_scan_id, job)?;
    let after = indexed_scan(&db, request.after_scan_id, job)?;
    let source_identity_matches = before_source
        .as_deref()
        .zip(after_source.as_deref())
        .is_some_and(|(before, after)| before == after);
    let mut remaining = before;
    let mut added = Vec::new();
    let mut size_changed = Vec::new();
    let mut same_size = 0usize;
    for (path, bytes) in after {
        job.check()?;
        match remaining.remove(&path) {
            None => added.push(json!({"path": path, "bytes": bytes})),
            Some(previous) if previous != bytes => size_changed.push(json!({
                "path": path,
                "before_bytes": previous,
                "after_bytes": bytes,
            })),
            Some(_) => same_size += 1,
        }
    }
    let removed = remaining
        .into_iter()
        .map(|(path, bytes)| json!({"path": path, "bytes": bytes}))
        .collect::<Vec<_>>();
    Ok(json!({
        "schema_version": 1,
        "before_scan_id": request.before_scan_id,
        "after_scan_id": request.after_scan_id,
        "before_root_label": before_label,
        "after_root_label": after_label,
        "before_scanned_unix_ms": before_time,
        "after_scanned_unix_ms": after_time,
        "source_identity_matches": source_identity_matches,
        "added": added,
        "removed": removed,
        "size_changed": size_changed,
        "same_size": same_size,
    }))
}

fn indexed_scan(db: &Connection, scan_id: i64, job: &Job) -> Result<BTreeMap<String, u64>> {
    let mut statement = db
        .prepare("SELECT path, bytes FROM files WHERE scan_id=?1 ORDER BY path")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_error)?;
    let mut result = BTreeMap::new();
    for row in rows {
        job.check()?;
        let (path, bytes) = row.map_err(sqlite_error)?;
        let bytes = bytes
            .parse::<u64>()
            .map_err(|_| Error::input("Catalogue contains an invalid file size"))?;
        if path.is_empty() || path.contains('\0') || result.insert(path, bytes).is_some() {
            return Err(Error::input("Catalogue snapshot contains an invalid path"));
        }
        if result.len() > 10_000 {
            return Err(Error::new(
                ErrorKind::Limit,
                "Catalogue scan exceeds 10,000 files",
            ));
        }
    }
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema_version: u32,
    files: Vec<Entry>,
    #[serde(default)]
    complete: Option<bool>,
    #[serde(default)]
    #[serde(rename = "warnings")]
    _warnings: Vec<String>,
    #[serde(default, rename = "omitted_warnings")]
    _omitted_warnings: usize,
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
    let files = if is_sqlite_path(catalog) {
        let db = open_catalog(catalog, false)?;
        latest_scan(&db, job)?.1
    } else {
        load(catalog, job)?.files
    };
    let query = query.to_lowercase();
    let scanned = files.len();
    let mut matches = Vec::new();
    for entry in files {
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
    if inventory.schema_version == 2 && inventory.complete == Some(false) {
        return Err(Error::input(
            "This scan is incomplete and cannot be searched or compared as a full inventory",
        ));
    }
    if inventory.schema_version != 1
        && !(inventory.schema_version == 2 && inventory.complete == Some(true))
    {
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
    let files = if is_sqlite_path(path) {
        let db = open_catalog(path, false)?;
        latest_scan(&db, job)?.1
    } else {
        load(path, job)?.files
    };
    for entry in files {
        job.check()?;
        if result.insert(entry.path, entry.bytes).is_some() {
            return Err(Error::input("Duplicate path in saved inventory"));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(files: &[(&str, u64)]) -> Vec<Entry> {
        files
            .iter()
            .map(|(path, bytes)| Entry {
                path: (*path).to_owned(),
                bytes: *bytes,
            })
            .collect()
    }

    #[test]
    fn same_filesystem_identity_reconciles_paths_across_mount_path_changes() {
        // Mount paths are deliberately absent from the matching contract. This
        // simulates a moved mount and a remount retaining the same filesystem ID.
        let before = entries(&[("keep", 1), ("change", 2), ("remove", 3)]);
        let after = entries(&[("keep", 1), ("change", 4), ("add", 5)]);
        let delta = reconcile(
            Some("unix-dev:42-ino:6"),
            Some("unix-dev:42-ino:6"),
            &before,
            &after,
        );
        assert_eq!(delta.mode, "same-source");
        assert_eq!((delta.added, delta.changed, delta.removed), (1, 1, 1));
    }

    #[cfg(unix)]
    #[test]
    fn source_identity_survives_a_different_path_to_the_same_directory() {
        let directory = tempfile::tempdir().unwrap();
        let original_mount_path = directory.path().join("volume-old");
        let new_mount_path = directory.path().join("volume-new");
        fs::create_dir(&original_mount_path).unwrap();
        std::os::unix::fs::symlink(&original_mount_path, &new_mount_path).unwrap();

        assert_eq!(
            stable_source_identity(&original_mount_path),
            stable_source_identity(&new_mount_path)
        );
    }

    #[cfg(windows)]
    #[test]
    fn source_identity_uses_volume_and_directory_ids_not_mount_path() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("catalogue-root");
        fs::create_dir(&root).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        assert_eq!(
            stable_source_identity(&root),
            stable_source_identity(&canonical)
        );
        assert!(stable_source_identity(&root).is_some());
    }

    #[test]
    fn changed_or_unknown_identity_forces_full_rescan_without_claiming_deltas() {
        let before = entries(&[("old", 1)]);
        let after = entries(&[("new", 1)]);
        for (previous, current) in [
            (Some("unix-dev:1-ino:9"), Some("unix-dev:2-ino:9")),
            (None, Some("unix-dev:2-ino:9")),
            (Some("unix-dev:1-ino:9"), None),
            (None, None),
        ] {
            let delta = reconcile(previous, current, &before, &after);
            assert_eq!(delta.mode, "full-rescan");
            assert_eq!((delta.added, delta.changed, delta.removed), (0, 0, 0));
        }
    }

    #[test]
    fn schema_v1_catalogue_migrates_without_dropping_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(&format!(
            "PRAGMA page_size=4096;
             PRAGMA application_id={CATALOG_APPLICATION_ID};
             PRAGMA user_version=1;
             CREATE TABLE scans(id INTEGER PRIMARY KEY, scanned_unix_ms INTEGER NOT NULL, root_label TEXT NOT NULL, file_count INTEGER NOT NULL, total_bytes TEXT NOT NULL);
             CREATE TABLE files(scan_id INTEGER NOT NULL REFERENCES scans(id), path TEXT NOT NULL, bytes TEXT NOT NULL, PRIMARY KEY(scan_id,path)) WITHOUT ROWID;
             INSERT INTO scans VALUES(1, 1000, 'Old disk', 1, '4');
             INSERT INTO files VALUES(1, 'old.txt', '4');"
        )).unwrap();
        drop(db);

        let migrated = open_catalog(&path, true).unwrap();
        let version: i64 = migrated
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let source_id: Option<String> = migrated
            .query_row("SELECT source_id FROM scans WHERE id=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let count: i64 = migrated
            .query_row("SELECT COUNT(*) FROM files WHERE scan_id=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 2);
        assert_eq!(source_id, None);
        assert_eq!(count, 1);
        drop(migrated);

        let root = directory.path().join("source");
        fs::create_dir(&root).unwrap();
        let refresh = refresh(
            &path,
            &root,
            &[json!({"path":"new.txt", "bytes":1})],
            &Job::new(),
        )
        .unwrap();
        assert_eq!(refresh["comparison_mode"], "full-rescan");
        let history = history(&path, &Job::new()).unwrap();
        assert_eq!(history["scans"][0]["comparison_mode"], "full-rescan");
        assert_eq!(history["scans"][1]["comparison_mode"], "unknown");
    }

    #[test]
    fn compares_selected_saved_snapshots_without_accessing_source_files() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source");
        fs::create_dir(&root).unwrap();
        let catalogue = directory.path().join("history.sqlite");
        create(
            &root,
            &[
                json!({"path":"keep.txt","bytes":4}),
                json!({"path":"change.txt","bytes":2}),
                json!({"path":"remove.txt","bytes":3}),
            ],
            &catalogue,
            &Job::new(),
        )
        .unwrap();
        refresh(
            &catalogue,
            &root,
            &[
                json!({"path":"keep.txt","bytes":4}),
                json!({"path":"change.txt","bytes":8}),
                json!({"path":"add.txt","bytes":5}),
            ],
            &Job::new(),
        )
        .unwrap();

        let report = compare_snapshots(
            &catalogue,
            r#"{"before_scan_id":1,"after_scan_id":2}"#,
            &Job::new(),
        )
        .unwrap();
        assert_eq!(report["source_identity_matches"], true);
        assert_eq!(report["added"][0]["path"], "add.txt");
        assert_eq!(report["removed"][0]["path"], "remove.txt");
        assert_eq!(report["size_changed"][0]["path"], "change.txt");
        assert_eq!(report["same_size"], 1);

        assert!(compare_snapshots(
            &catalogue,
            r#"{"before_scan_id":1,"after_scan_id":1}"#,
            &Job::new(),
        )
        .is_err());
        assert!(compare_snapshots(
            &catalogue,
            r#"{"before_scan_id":1,"after_scan_id":99}"#,
            &Job::new(),
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn catalogue_open_canonicalizes_symlinked_parent_but_rejects_final_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source");
        let real_parent = directory.path().join("real-parent");
        let linked_parent = directory.path().join("linked-parent");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&real_parent).unwrap();
        let catalogue = real_parent.join("catalogue.sqlite");
        create(&root, &[], &catalogue, &Job::new()).unwrap();
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();

        assert!(history(&linked_parent.join("catalogue.sqlite"), &Job::new()).is_ok());
        let final_symlink = directory.path().join("final-link.sqlite");
        std::os::unix::fs::symlink(&catalogue, &final_symlink).unwrap();
        assert!(history(&final_symlink, &Job::new()).is_err());
    }
}
