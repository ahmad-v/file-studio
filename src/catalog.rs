use localwright_core::{read_bounded, write_new, Error, ErrorKind, Job, Result};
use rusqlite::{config::DbConfig, limits::Limit, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs, io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const CATALOG_APPLICATION_ID: i64 = 0x4c57_5243;
const CATALOG_SCHEMA_VERSION: i64 = 1;
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
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
    };
    let db = Connection::open_with_flags(path, flags).map_err(sqlite_error)?;
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
        || version != CATALOG_SCHEMA_VERSION
        || page_size != 4096
    {
        return Err(Error::input(
            "Unsupported or non-File-Studio catalogue database",
        ));
    }
    Ok(db)
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

fn insert_scan(db: &mut Connection, label: &str, files: &[Value], job: &Job) -> Result<i64> {
    if files.len() > 10_000 {
        return Err(Error::new(ErrorKind::Limit, "Scan exceeds 10,000 files"));
    }
    let scanned_at = scanned_unix_ms()?;
    let transaction = db.transaction().map_err(sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO scans(scanned_unix_ms, root_label, file_count, total_bytes) VALUES(?1, ?2, 0, '0')",
            (scanned_at, label),
        )
        .map_err(sqlite_error)?;
    let scan_id = transaction.last_insert_rowid();
    let mut total_bytes = 0u128;
    {
        let mut insert = transaction
            .prepare("INSERT INTO files(scan_id, path, bytes) VALUES(?1, ?2, ?3)")
            .map_err(sqlite_error)?;
        for file in files {
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
         CREATE TABLE scans(id INTEGER PRIMARY KEY, scanned_unix_ms INTEGER NOT NULL, root_label TEXT NOT NULL, file_count INTEGER NOT NULL, total_bytes TEXT NOT NULL);
         CREATE TABLE files(scan_id INTEGER NOT NULL REFERENCES scans(id), path TEXT NOT NULL, bytes TEXT NOT NULL, PRIMARY KEY(scan_id,path)) WITHOUT ROWID;
         CREATE INDEX files_path ON files(path);",
        MAX_CATALOG_BYTES / 4096,
        CATALOG_APPLICATION_ID,
        CATALOG_SCHEMA_VERSION,
    ))
    .map_err(sqlite_error)?;
    let scan_id = insert_scan(&mut db, &root_label(&root), files, job)?;
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
    let transaction_will_add_history = insert_scan(&mut db, &root_label(&root), files, job)?;
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
        "history": true,
    }))
}

pub fn history(path: &Path, job: &Job) -> Result<Value> {
    let db = open_catalog(path, false)?;
    let mut statement = db
        .prepare("SELECT id, scanned_unix_ms, root_label, file_count, total_bytes FROM scans ORDER BY id DESC LIMIT 101")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok(json!({
                "scan_id": row.get::<_, i64>(0)?,
                "scanned_unix_ms": row.get::<_, i64>(1)?,
                "root_label": row.get::<_, String>(2)?,
                "files": row.get::<_, i64>(3)?,
                "total_bytes": row.get::<_, String>(4)?,
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
