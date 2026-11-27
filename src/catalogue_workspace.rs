//! Bounded view models for the native catalogue workspace.

use serde::Deserialize;

const MAX_ROWS: usize = 10_000;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SearchReport {
    pub schema_version: u32,
    pub catalogued_files: usize,
    pub matched_files: usize,
    pub files: Vec<CatalogueFile>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogueFile {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoryReport {
    pub schema_version: u32,
    pub scans: Vec<ScanSummary>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DuplicateReport {
    pub schema_version: u32,
    pub regular_files_scanned: usize,
    pub groups: Vec<DuplicateGroup>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DuplicateGroup {
    pub bytes_per_file: u64,
    pub blake3: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanSummary {
    pub scan_id: i64,
    pub scanned_unix_ms: i64,
    pub root_label: String,
    pub files: i64,
    pub total_bytes: String,
    #[serde(default)]
    pub comparison_mode: String,
    #[serde(default)]
    pub added: i64,
    #[serde(default)]
    pub changed: i64,
    #[serde(default)]
    pub removed: i64,
}

impl SearchReport {
    pub fn parse(input: &str) -> Result<Self, String> {
        let report: Self = serde_json::from_str(input).map_err(|error| error.to_string())?;
        if report.schema_version != 1 {
            return Err("Unsupported catalogue search report version".into());
        }
        if report.files.len() > MAX_ROWS
            || report.matched_files != report.files.len()
            || report.catalogued_files < report.matched_files
            || report.files.iter().any(|entry| {
                entry.path.is_empty() || entry.path.len() > 64 * 1024 || entry.path.contains('\0')
            })
        {
            return Err("Catalogue search report is inconsistent or exceeds display limits".into());
        }
        Ok(report)
    }
}

impl HistoryReport {
    pub fn parse(input: &str) -> Result<Self, String> {
        let report: Self = serde_json::from_str(input).map_err(|error| error.to_string())?;
        if !(1..=2).contains(&report.schema_version) {
            return Err("Unsupported catalogue history report version".into());
        }
        if report.scans.len() > 100
            || report.scans.iter().any(|scan| {
                scan.scan_id < 1
                    || scan.scanned_unix_ms < 0
                    || scan.files < 0
                    || scan.root_label.is_empty()
                    || scan.root_label.len() > 255
                    || scan.total_bytes.parse::<u128>().is_err()
                    || scan.added < 0
                    || scan.changed < 0
                    || scan.removed < 0
                    || !["", "unknown", "baseline", "same-source", "full-rescan"]
                        .contains(&scan.comparison_mode.as_str())
            })
        {
            return Err("Catalogue history report is invalid or exceeds display limits".into());
        }
        Ok(report)
    }
}

impl DuplicateReport {
    pub fn parse(input: &str) -> Result<Self, String> {
        const MAX_CANDIDATES: usize = 10_000;
        let report: Self = serde_json::from_str(input).map_err(|error| error.to_string())?;
        let candidate_count = report
            .groups
            .iter()
            .try_fold(0usize, |count, group| count.checked_add(group.paths.len()));
        let Some(candidate_count) = candidate_count else {
            return Err("Duplicate candidate report size overflows display limits".into());
        };
        if report.schema_version != 1
            || report.regular_files_scanned > MAX_ROWS
            || report.groups.len() > MAX_ROWS
            || candidate_count > MAX_CANDIDATES
            || candidate_count > report.regular_files_scanned
            || report.groups.iter().any(|group| {
                group.paths.len() < 2
                    || group.blake3.len() != 64
                    || !group.blake3.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || group.paths.iter().any(|path| {
                        path.is_empty() || path.len() > 64 * 1024 || path.contains('\0')
                    })
            })
        {
            return Err(
                "Duplicate candidate report is inconsistent or exceeds display limits".into(),
            );
        }
        Ok(report)
    }
}

/// Replace path control characters so one unusual filename cannot create extra table rows.
pub fn display_path(path: &str) -> String {
    path.chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

pub fn format_bytes(bytes: u128) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_search_results_and_rejects_inconsistent_counts() {
        let report = SearchReport::parse(
            r#"{"schema_version":1,"catalogued_files":3,"matched_files":1,"files":[{"path":"papers/a.pdf","bytes":2048}]}"#,
        )
        .unwrap();
        assert_eq!(report.files[0].path, "papers/a.pdf");
        assert_eq!(report.files[0].bytes, 2048);

        assert!(SearchReport::parse(
            r#"{"schema_version":1,"catalogued_files":3,"matched_files":2,"files":[{"path":"a","bytes":1}]}"#
        )
        .is_err());
    }

    #[test]
    fn parses_history_and_bounds_displayed_rows() {
        let report = HistoryReport::parse(
            r#"{"schema_version":2,"scans":[{"scan_id":3,"scanned_unix_ms":1760000000000,"root_label":"Research","files":7,"total_bytes":"987654321","comparison_mode":"same-source","added":2,"changed":1,"removed":3}],"truncated":false}"#,
        )
        .unwrap();
        assert_eq!(report.scans[0].root_label, "Research");
        assert_eq!(report.scans[0].comparison_mode, "same-source");
        assert!(
            HistoryReport::parse(r#"{"schema_version":3,"scans":[],"truncated":false}"#).is_err()
        );
    }

    #[test]
    fn parses_content_hash_duplicate_candidates_and_rejects_invalid_groups() {
        let report = DuplicateReport::parse(
            r#"{"schema_version":1,"regular_files_scanned":4,"groups":[{"bytes_per_file":3,"blake3":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","paths":["a.txt","copy/a.txt"]}]}"#,
        )
        .unwrap();
        assert_eq!(report.groups[0].paths.len(), 2);
        assert!(DuplicateReport::parse(
            r#"{"schema_version":1,"regular_files_scanned":2,"groups":[{"bytes_per_file":3,"blake3":"not-a-digest","paths":["a.txt","b.txt"]}]}"#
        )
        .is_err());
        assert!(DuplicateReport::parse(
            r#"{"schema_version":1,"regular_files_scanned":2,"groups":[{"bytes_per_file":3,"blake3":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","paths":["a.txt"]}]}"#
        )
        .is_err());
    }

    #[test]
    fn paths_are_safe_for_single_line_tables_and_sizes_are_readable() {
        assert_eq!(display_path("papers\nsecret.pdf"), "papers�secret.pdf");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(42), "42 B");
    }
}
