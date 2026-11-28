#![forbid(unsafe_code)]

use file_studio::catalogue_workspace::{
    display_path, format_bytes, usage_fraction, CatalogueFile, DirectoryUsageReport,
    DuplicateReport, HistoryReport, ScanSummary, SearchReport,
};
use futures::channel::oneshot;
use iced::{
    keyboard::{key::Named, Key, Modifiers},
    theme::Palette,
    widget::{
        button, column, container, pick_list, progress_bar, row, scrollable, text, text_input,
    },
    Color, Element, Length, Subscription, Task, Theme,
};
use localwright_core::{Error, ErrorKind, Handler, Job, Operation, Outcome, Request};
use localwright_ui::{
    paginated_table, CellValue, SortDirection, TableAction, TableModel, TableState, THEMES,
};
use serde::{Deserialize, Serialize};
use std::{
    env, fmt, fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

const SCALES: [u16; 7] = [80, 100, 125, 150, 200, 250, 300];
const DUPLICATE_PAGE_SIZE: usize = 20;

fn selected_or_typed(selected: Option<&PathBuf>, typed: &str) -> PathBuf {
    selected.cloned().unwrap_or_else(|| PathBuf::from(typed))
}

fn search_table_model(rows: &[CatalogueFile]) -> Result<TableModel, String> {
    let rows = rows
        .iter()
        .map(|entry| {
            vec![
                CellValue::Text(display_path(&entry.path)),
                CellValue::UnsignedInteger(entry.bytes),
            ]
        })
        .collect();
    TableModel::new(vec!["Relative path".into(), "Bytes".into()], rows)
        .map_err(|error| error.to_string())
}

fn history_table_model(rows: &[ScanSummary]) -> Result<TableModel, String> {
    let sizes = rows
        .iter()
        .map(|scan| scan.total_bytes.parse::<u64>())
        .collect::<Result<Vec<_>, _>>();
    let size_is_numeric = sizes.is_ok();
    let mut cells = Vec::with_capacity(rows.len());
    for (index, scan) in rows.iter().enumerate() {
        let scan_label = format!("#{} · {}", scan.scan_id, display_path(&scan.root_label));
        let total_bytes = if size_is_numeric {
            CellValue::UnsignedInteger(sizes.as_ref().expect("validated above")[index])
        } else {
            CellValue::Text(scan.total_bytes.clone())
        };
        let delta = if scan.comparison_mode == "same-source" {
            format!("+{} ~{} −{}", scan.added, scan.changed, scan.removed)
        } else if scan.comparison_mode == "full-rescan" {
            "Full rescan; identity changed/unknown".to_owned()
        } else if scan.comparison_mode == "unknown" {
            "Legacy snapshot; identity unknown".to_owned()
        } else {
            "Baseline".to_owned()
        };
        cells.push(vec![
            CellValue::Text(scan_label),
            CellValue::UnsignedInteger(scan.files as u64),
            total_bytes,
            CellValue::Text(delta),
            CellValue::Integer(scan.scanned_unix_ms),
        ]);
    }
    let bytes_header = if size_is_numeric {
        "Total bytes"
    } else {
        "Total bytes (text)"
    };
    TableModel::new(
        vec![
            "Scan / source".into(),
            "Files".into(),
            bytes_header.into(),
            "Refresh delta".into(),
            "Timestamp (UTC ms)".into(),
        ],
        cells,
    )
    .map_err(|error| error.to_string())
}

fn is_sqlite_catalogue_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("sqlite") || extension.eq_ignore_ascii_case("sqlite3")
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Catalogue,
    Operations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    CreateCatalogue,
    BackupCatalogue,
    Search,
    History,
    Refresh,
    Usage,
    CompareSnapshots,
    Duplicates,
    InspectSelection,
    Operation,
}

#[derive(Debug, Clone, PartialEq)]
struct ProgressPresentation {
    label: String,
    fraction: Option<f32>,
}

fn progress_presentation(kind: RequestKind, fraction: Option<f32>) -> ProgressPresentation {
    match (kind, fraction) {
        (RequestKind::Refresh | RequestKind::CreateCatalogue | RequestKind::Usage, None) => {
            ProgressPresentation {
                label: if kind == RequestKind::Usage {
                    "Analyzing folder sizes; progress is indeterminate.".into()
                } else {
                    "Scanning folder; progress is indeterminate.".into()
                },
                fraction: None,
            }
        }
        (RequestKind::Refresh, Some(fraction)) => ProgressPresentation {
            label: format!(
                "Saving catalogue snapshot: {:.0}% complete",
                fraction * 100.0
            ),
            fraction: Some(fraction.clamp(0.0, 1.0)),
        },
        (_, None) => ProgressPresentation {
            label: format!(
                "{} is running; progress is indeterminate.",
                request_title(kind)
            ),
            fraction: None,
        },
        (_, Some(fraction)) => ProgressPresentation {
            label: format!(
                "{} progress: {:.0}% complete",
                request_title(kind),
                fraction * 100.0
            ),
            fraction: Some(fraction.clamp(0.0, 1.0)),
        },
    }
}

#[derive(Debug, Clone, Copy)]
struct OperationChoice(&'static Operation);

impl PartialEq for OperationChoice {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl fmt::Display for OperationChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.label)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    schema_version: u32,
    theme: String,
    scale: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shortcuts: Option<serde_json::Value>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            schema_version: 1,
            theme: "Modern Light".into(),
            scale: 100,
            shortcuts: None,
        }
    }
}

impl Preferences {
    fn load(path: &Path) -> localwright_core::Result<Self> {
        let bytes = match localwright_core::read_bounded(path, 4096) {
            Ok(bytes) => bytes,
            Err(error) if error.kind == ErrorKind::Io && !path.exists() => {
                return Ok(Self::default())
            }
            Err(error) => return Err(error),
        };
        let settings: Self = serde_json::from_slice(&bytes)?;
        settings.validate()?;
        Ok(settings)
    }

    fn save(&self, path: &Path) -> localwright_core::Result<()> {
        self.validate()?;
        // Do not replace a settings document written by a newer or unknown version.
        Self::load(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| Error::input("Preferences path has no parent directory"))?;
        fs::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(&mut temporary, self)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(path)
            .map_err(|error| Error::from(error.error))?;
        Ok(())
    }

    fn validate(&self) -> localwright_core::Result<()> {
        if self.schema_version != 1
            || !THEMES.iter().any(|preset| preset.0 == self.theme)
            || !SCALES.contains(&self.scale)
        {
            return Err(Error::input(
                "Unsupported File Studio workbench preferences",
            ));
        }
        Ok(())
    }
}

fn preferences_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let base = env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base =
        env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Application Support"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    base.filter(|path| path.is_absolute())
        .map(|base| base.join("file-studio").join("workbench.json"))
}

struct StudioUi {
    operations: &'static [Operation],
    handler: Handler,
    page: Page,
    preferences: Preferences,
    preferences_path: Option<PathBuf>,
    settings_unwritable: bool,
    preferences_error: Option<String>,
    catalogue_path: String,
    catalogue_selection: Option<PathBuf>,
    root_path: String,
    root_selection: Option<PathBuf>,
    query: String,
    search_results: Option<SearchReport>,
    search_table: Option<TableModel>,
    search_table_state: TableState,
    history: Vec<file_studio::catalogue_workspace::ScanSummary>,
    history_table_rows: Vec<ScanSummary>,
    history_table: Option<TableModel>,
    history_table_state: TableState,
    history_truncated: bool,
    duplicate_report: Option<DuplicateReport>,
    duplicate_page_index: usize,
    usage_report: Option<DirectoryUsageReport>,
    compare_before: String,
    compare_after: String,
    comparison_report: Option<String>,
    inspection_path: Option<String>,
    inspection_catalogued_bytes: Option<u64>,
    inspection_report: Option<String>,
    selected_operation: String,
    input_path: String,
    input_selection: Option<PathBuf>,
    output_path: String,
    output_selection: Option<PathBuf>,
    parameter: String,
    operation_preview: String,
    status: String,
    job: Option<Job>,
    job_kind: Option<RequestKind>,
}

#[derive(Debug, Clone)]
enum Message {
    Page(Page),
    Theme(String),
    Scale(u16),
    CataloguePath(String),
    RootPath(String),
    Query(String),
    BrowseCatalogue,
    CreateCatalogue,
    BackupCatalogue,
    CataloguePicked(Option<PathBuf>),
    CatalogueCreatedPath(Option<PathBuf>),
    CatalogueBackupPath(Option<PathBuf>),
    BrowseRoot,
    RootPicked(Option<PathBuf>),
    Search,
    SearchTableAction(TableAction),
    LoadHistory,
    Refresh,
    AnalyzeUsage,
    FindDuplicates,
    CompareSnapshots,
    HistoryTableAction(TableAction),
    CompareBefore(String),
    CompareAfter(String),
    InspectCatalogueFile(String),
    PreviousDuplicatePage,
    NextDuplicatePage,
    Operation(String),
    Input(String),
    Output(String),
    Parameter(String),
    BrowseInputFile,
    BrowseInputFolder,
    InputPicked(Option<PathBuf>),
    BrowseOutput,
    OutputPicked(Option<PathBuf>),
    RunOperation,
    Cancel,
    KeyPressed(Key, Modifiers),
    RequestFinished(RequestKind, localwright_core::Result<Outcome>),
    ProgressTick,
}

impl StudioUi {
    fn new(operations: &'static [Operation], handler: Handler) -> Self {
        let path = preferences_path();
        let (preferences, preferences_error, settings_unwritable) = match path.as_deref() {
            Some(path) => match Preferences::load(path) {
                Ok(preferences) => (preferences, None, false),
                Err(error) => (
                    Preferences::default(),
                    Some(format!("Could not load workbench preferences: {error}")),
                    true,
                ),
            },
            None => (
                Preferences::default(),
                Some("User configuration directory is unavailable".into()),
                true,
            ),
        };
        Self {
            operations,
            handler,
            page: Page::Catalogue,
            preferences,
            preferences_path: path,
            settings_unwritable,
            preferences_error,
            catalogue_path: String::new(),
            catalogue_selection: None,
            root_path: String::new(),
            root_selection: None,
            query: String::new(),
            search_results: None,
            search_table: None,
            search_table_state: TableState::new(50),
            history: Vec::new(),
            history_table_rows: Vec::new(),
            history_table: None,
            history_table_state: TableState::new(20),
            history_truncated: false,
            duplicate_report: None,
            duplicate_page_index: 0,
            usage_report: None,
            compare_before: String::new(),
            compare_after: String::new(),
            comparison_report: None,
            inspection_path: None,
            inspection_catalogued_bytes: None,
            inspection_report: None,
            selected_operation: operations
                .first()
                .map_or_else(String::new, |operation| operation.id.to_owned()),
            input_path: String::new(),
            input_selection: None,
            output_path: String::new(),
            output_selection: None,
            parameter: String::new(),
            operation_preview: String::new(),
            status: "Open a saved catalogue or create one from the Operations page.".into(),
            job: None,
            job_kind: None,
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Page(page) => self.page = page,
            Message::Theme(theme) => {
                self.preferences.theme = theme;
                self.save_preferences();
            }
            Message::Scale(scale) => {
                self.preferences.scale = scale;
                self.save_preferences();
            }
            Message::CataloguePath(path) => {
                self.catalogue_path = path;
                self.catalogue_selection = None;
                self.search_results = None;
                self.search_table = None;
                self.history.clear();
                self.history_table_rows.clear();
                self.history_table = None;
                self.inspection_path = None;
                self.inspection_catalogued_bytes = None;
                self.inspection_report = None;
                self.search_table_state = TableState::new(50);
                self.history_table_state = TableState::new(20);
                self.status =
                    "Select a saved catalogue, then search paths or load its history.".into();
            }
            Message::RootPath(path) => {
                self.root_path = path;
                self.root_selection = None;
                self.duplicate_report = None;
                self.duplicate_page_index = 0;
                self.usage_report = None;
                self.inspection_path = None;
                self.inspection_catalogued_bytes = None;
                self.inspection_report = None;
            }
            Message::Query(query) => {
                self.query = query;
                self.search_results = None;
                self.search_table = None;
                self.search_table_state = TableState::new(50);
                self.inspection_path = None;
                self.inspection_catalogued_bytes = None;
                self.inspection_report = None;
            }
            Message::BrowseCatalogue => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Open File Studio catalogue")
                            .add_filter("File Studio catalogue", &["sqlite", "sqlite3"])
                            .pick_file()
                            .await
                            .map(|file| file.path().to_path_buf())
                    },
                    Message::CataloguePicked,
                );
            }
            Message::CreateCatalogue => {
                if self.job.is_some() {
                    return Task::none();
                }
                if self.root_path.trim().is_empty() {
                    self.status = "Choose the source folder before creating a catalogue.".into();
                    return Task::none();
                }
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Create a new File Studio catalogue")
                            .add_filter("SQLite catalogue", &["sqlite"])
                            .set_file_name("catalogue.sqlite")
                            .save_file()
                            .await
                            .map(|file| file.path().to_path_buf())
                    },
                    Message::CatalogueCreatedPath,
                );
            }
            Message::BackupCatalogue => {
                if self.job.is_some() || self.catalogue_path.trim().is_empty() {
                    self.status = "Open a saved SQLite catalogue before backing it up.".into();
                    return Task::none();
                }
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Create a catalogue database backup")
                            .add_filter("SQLite catalogue backup", &["sqlite", "sqlite3"])
                            .set_file_name("catalogue-backup.sqlite")
                            .save_file()
                            .await
                            .map(|file| file.path().to_path_buf())
                    },
                    Message::CatalogueBackupPath,
                );
            }
            Message::CatalogueCreatedPath(Some(path)) => {
                if !is_sqlite_catalogue_path(&path) {
                    self.status = "Choose a .sqlite or .sqlite3 catalogue path.".into();
                    return Task::none();
                }
                let request = Request {
                    operation: "scan".into(),
                    input: selected_or_typed(self.root_selection.as_ref(), &self.root_path),
                    output: path,
                    ..Request::default()
                };
                return self.submit(RequestKind::CreateCatalogue, request);
            }
            Message::CatalogueCreatedPath(None) => {}
            Message::CatalogueBackupPath(Some(path)) => {
                if !is_sqlite_catalogue_path(&path) {
                    self.status = "Choose a .sqlite or .sqlite3 backup path.".into();
                    return Task::none();
                }
                let request = Request {
                    operation: "catalog-backup".into(),
                    input: selected_or_typed(
                        self.catalogue_selection.as_ref(),
                        &self.catalogue_path,
                    ),
                    output: path,
                    ..Request::default()
                };
                return self.submit(RequestKind::BackupCatalogue, request);
            }
            Message::CatalogueBackupPath(None) => {}
            Message::CataloguePicked(path) => {
                if let Some(path) = path {
                    self.catalogue_path = path.to_string_lossy().into_owned();
                    self.catalogue_selection = Some(path);
                    self.search_results = None;
                    self.search_table = None;
                    self.history.clear();
                    self.history_table_rows.clear();
                    self.history_table = None;
                    self.search_table_state = TableState::new(50);
                    self.history_table_state = TableState::new(20);
                    self.inspection_path = None;
                    self.inspection_catalogued_bytes = None;
                    self.inspection_report = None;
                    return self.start_history();
                }
            }
            Message::BrowseRoot => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Choose a folder to scan")
                            .pick_folder()
                            .await
                            .map(|folder| folder.path().to_path_buf())
                    },
                    Message::RootPicked,
                );
            }
            Message::RootPicked(path) => {
                if let Some(path) = path {
                    self.root_path = path.to_string_lossy().into_owned();
                    self.root_selection = Some(path);
                    self.duplicate_report = None;
                    self.duplicate_page_index = 0;
                    self.usage_report = None;
                    self.inspection_path = None;
                    self.inspection_catalogued_bytes = None;
                    self.inspection_report = None;
                }
            }
            Message::Search => return self.start_search(),
            Message::SearchTableAction(action) => self.search_table_action(action),
            Message::LoadHistory => return self.start_history(),
            Message::Refresh => return self.start_refresh(),
            Message::FindDuplicates => return self.start_duplicate_review(),
            Message::AnalyzeUsage => return self.start_directory_usage(),
            Message::CompareBefore(value) => self.compare_before = value,
            Message::CompareAfter(value) => self.compare_after = value,
            Message::CompareSnapshots => return self.start_snapshot_comparison(),
            Message::HistoryTableAction(action) => self.history_table_action(action),
            Message::InspectCatalogueFile(relative) => {
                return self.start_catalogue_inspection(relative)
            }
            Message::PreviousDuplicatePage => {
                self.duplicate_page_index = self.duplicate_page_index.saturating_sub(1)
            }
            Message::NextDuplicatePage => {
                if self.duplicate_page_index + 1 < self.duplicate_page_count() {
                    self.duplicate_page_index += 1;
                }
            }
            Message::Operation(operation) => self.selected_operation = operation,
            Message::Input(input) => {
                self.input_path = input;
                self.input_selection = None;
            }
            Message::Output(output) => {
                self.output_path = output;
                self.output_selection = None;
            }
            Message::Parameter(parameter) => self.parameter = parameter,
            Message::BrowseInputFile => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Select operation input file")
                            .pick_file()
                            .await
                            .map(|file| file.path().to_path_buf())
                    },
                    Message::InputPicked,
                );
            }
            Message::BrowseInputFolder => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Select operation input folder")
                            .pick_folder()
                            .await
                            .map(|folder| folder.path().to_path_buf())
                    },
                    Message::InputPicked,
                );
            }
            Message::InputPicked(path) => {
                if let Some(path) = path {
                    self.input_path = path.to_string_lossy().into_owned();
                    self.input_selection = Some(path);
                }
            }
            Message::BrowseOutput => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_title("Choose a new output file")
                            .save_file()
                            .await
                            .map(|file| file.path().to_path_buf())
                    },
                    Message::OutputPicked,
                );
            }
            Message::OutputPicked(path) => {
                if let Some(path) = path {
                    self.output_path = path.to_string_lossy().into_owned();
                    self.output_selection = Some(path);
                }
            }
            Message::RunOperation => return self.start_operation(),
            Message::Cancel => {
                if let Some(job) = &self.job {
                    job.cancel();
                    self.status =
                        "Cancellation requested; waiting for the operation to stop.".into();
                }
            }
            Message::ProgressTick => {}
            Message::KeyPressed(Key::Named(Named::Escape), _) => {
                return self.update(Message::Cancel);
            }
            Message::KeyPressed(Key::Named(Named::Enter), modifiers)
                if self.page == Page::Operations && modifiers.command() =>
            {
                return self.update(Message::RunOperation);
            }
            Message::KeyPressed(_, _) => {}
            Message::RequestFinished(kind, result) => {
                self.job = None;
                self.job_kind = None;
                match result {
                    Ok(outcome) => return self.finish_request(kind, outcome),
                    Err(error) => {
                        self.status = format!("{} failed: {}", request_title(kind), error.message);
                        match kind {
                            RequestKind::Operation => self.operation_preview = error.message,
                            RequestKind::Duplicates => self.duplicate_report = None,
                            RequestKind::Usage => self.usage_report = None,
                            RequestKind::InspectSelection => {
                                self.inspection_report =
                                    Some(format!("Inspection failed: {}", error.message));
                            }
                            RequestKind::CompareSnapshots => {
                                self.comparison_report =
                                    Some(format!("Comparison failed: {}", error.message));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        Task::none()
    }

    fn start_search(&mut self) -> Task<Message> {
        if self.job.is_some() {
            return Task::none();
        }
        let query = self.query.trim();
        if self.catalogue_path.trim().is_empty() || query.is_empty() {
            self.status = "Choose a saved catalogue and enter a path fragment to search.".into();
            return Task::none();
        }
        if query.len() > 4096 {
            self.status = "Search text must be at most 4 KiB.".into();
            return Task::none();
        }
        self.inspection_path = None;
        self.inspection_catalogued_bytes = None;
        self.inspection_report = None;
        self.search_results = None;
        self.search_table = None;
        self.search_table_state = TableState::new(50);
        let request = Request {
            operation: "catalog-search".into(),
            input: selected_or_typed(self.catalogue_selection.as_ref(), &self.catalogue_path),
            parameter: query.to_owned(),
            ..Request::default()
        };
        self.submit(RequestKind::Search, request)
    }

    fn start_history(&mut self) -> Task<Message> {
        if self.job.is_some() {
            return Task::none();
        }
        if self.catalogue_path.trim().is_empty() {
            self.status = "Choose a saved SQLite catalogue to load its scan history.".into();
            return Task::none();
        }
        let request = Request {
            operation: "catalog-history".into(),
            input: selected_or_typed(self.catalogue_selection.as_ref(), &self.catalogue_path),
            ..Request::default()
        };
        self.submit(RequestKind::History, request)
    }

    fn start_refresh(&mut self) -> Task<Message> {
        if self.job.is_some() {
            return Task::none();
        }
        if self.catalogue_path.trim().is_empty() || self.root_path.trim().is_empty() {
            self.status = "Choose an existing SQLite catalogue and a folder to rescan.".into();
            return Task::none();
        }
        self.duplicate_report = None;
        self.duplicate_page_index = 0;
        self.usage_report = None;
        let request = Request {
            operation: "workspace-catalog-refresh".into(),
            input: selected_or_typed(self.root_selection.as_ref(), &self.root_path),
            output: selected_or_typed(self.catalogue_selection.as_ref(), &self.catalogue_path),
            ..Request::default()
        };
        self.submit(RequestKind::Refresh, request)
    }

    fn start_duplicate_review(&mut self) -> Task<Message> {
        if self.job.is_some() {
            return Task::none();
        }
        if self.root_path.trim().is_empty() {
            self.status = "Choose the source folder before checking duplicate candidates.".into();
            return Task::none();
        }
        self.duplicate_report = None;
        self.duplicate_page_index = 0;
        let request = Request {
            operation: "duplicates".into(),
            input: selected_or_typed(self.root_selection.as_ref(), &self.root_path),
            ..Request::default()
        };
        self.submit(RequestKind::Duplicates, request)
    }

    fn start_directory_usage(&mut self) -> Task<Message> {
        if self.job.is_some() {
            return Task::none();
        }
        if self.root_path.trim().is_empty() {
            self.status = "Choose a source folder before analyzing directory usage.".into();
            return Task::none();
        }
        self.usage_report = None;
        let request = Request {
            operation: "directory-usage".into(),
            input: selected_or_typed(self.root_selection.as_ref(), &self.root_path),
            ..Request::default()
        };
        self.submit(RequestKind::Usage, request)
    }

    fn search_table_action(&mut self, action: TableAction) {
        match action {
            TableAction::PageChanged(page) => self.search_table_state.set_page(
                page,
                self.search_results
                    .as_ref()
                    .map_or(0, |report| report.files.len()),
            ),
            TableAction::SelectRow(row) => self.search_table_state.select_row(
                row,
                self.search_results
                    .as_ref()
                    .map_or(0, |report| report.files.len()),
            ),
            TableAction::SortBy { column, direction } => {
                let Some(report) = self.search_results.as_mut() else {
                    return;
                };
                report.files.sort_by(|left, right| {
                    let order = match column {
                        0 => left.path.cmp(&right.path),
                        1 => left.bytes.cmp(&right.bytes),
                        _ => std::cmp::Ordering::Equal,
                    };
                    if direction == SortDirection::Descending {
                        order.reverse()
                    } else {
                        order
                    }
                });
                self.search_table_state.set_sort(column, direction);
                self.search_table_state
                    .select_row(usize::MAX, report.files.len());
                match search_table_model(&report.files) {
                    Ok(table) => self.search_table = Some(table),
                    Err(error) => self.status = format!("Could not sort search results: {error}"),
                }
            }
        }
    }

    fn history_table_action(&mut self, action: TableAction) {
        match action {
            TableAction::PageChanged(page) => self
                .history_table_state
                .set_page(page, self.history_table_rows.len()),
            TableAction::SelectRow(row) => {
                self.history_table_state
                    .select_row(row, self.history_table_rows.len());
                if let Some(scan) = self.history_table_rows.get(row) {
                    let scan_id = scan.scan_id.to_string();
                    if self.compare_before.is_empty() || !self.compare_after.is_empty() {
                        self.compare_before = scan_id;
                        self.compare_after.clear();
                    } else {
                        self.compare_after = scan_id;
                    }
                }
            }
            TableAction::SortBy { column, direction } => {
                self.history_table_rows.sort_by(|left, right| {
                    let ordering = match column {
                        0 => left.scan_id.cmp(&right.scan_id),
                        1 => left.files.cmp(&right.files),
                        2 => left
                            .total_bytes
                            .parse::<u128>()
                            .unwrap_or(u128::MAX)
                            .cmp(&right.total_bytes.parse::<u128>().unwrap_or(u128::MAX)),
                        3 => left.comparison_mode.cmp(&right.comparison_mode),
                        4 => left.scanned_unix_ms.cmp(&right.scanned_unix_ms),
                        _ => std::cmp::Ordering::Equal,
                    };
                    if direction == SortDirection::Descending {
                        ordering.reverse()
                    } else {
                        ordering
                    }
                });
                self.history_table_state.set_sort(column, direction);
                self.history_table_state
                    .select_row(usize::MAX, self.history_table_rows.len());
                match history_table_model(&self.history_table_rows) {
                    Ok(table) => self.history_table = Some(table),
                    Err(error) => self.status = format!("Could not sort scan history: {error}"),
                }
            }
        }
    }

    fn start_catalogue_inspection(&mut self, relative: String) -> Task<Message> {
        if self.job.is_some() {
            return Task::none();
        }
        if self.root_path.trim().is_empty() {
            self.status = "Choose the source folder represented by this catalogue before inspecting a result.".into();
            return Task::none();
        }
        if !self.search_results.as_ref().is_some_and(|results| {
            results
                .files
                .iter()
                .any(|entry| entry.path.as_str() == relative.as_str())
        }) {
            self.status = "Search again before inspecting a catalogue result.".into();
            return Task::none();
        }
        self.inspection_catalogued_bytes = self
            .search_results
            .as_ref()
            .and_then(|results| {
                results
                    .files
                    .iter()
                    .find(|entry| entry.path.as_str() == relative.as_str())
            })
            .map(|entry| entry.bytes);
        self.inspection_path = Some(relative.clone());
        self.inspection_report = Some("Inspection running…".into());
        let request = Request {
            operation: "workspace-catalog-inspect".into(),
            input: selected_or_typed(self.root_selection.as_ref(), &self.root_path),
            parameter: relative,
            ..Request::default()
        };
        self.submit(RequestKind::InspectSelection, request)
    }

    fn start_snapshot_comparison(&mut self) -> Task<Message> {
        if self.job.is_some() {
            return Task::none();
        }
        let (Ok(before), Ok(after)) = (
            self.compare_before.trim().parse::<i64>(),
            self.compare_after.trim().parse::<i64>(),
        ) else {
            self.status = "Enter two scan IDs shown in the history table.".into();
            return Task::none();
        };
        if before < 1 || after < 1 || before == after {
            self.status = "Choose two different positive scan IDs.".into();
            return Task::none();
        }
        if self.catalogue_path.trim().is_empty() {
            self.status = "Open a saved SQLite catalogue before comparing snapshots.".into();
            return Task::none();
        }
        let request = Request {
            operation: "catalog-compare-snapshots".into(),
            input: selected_or_typed(self.catalogue_selection.as_ref(), &self.catalogue_path),
            parameter: serde_json::json!({
                "before_scan_id": before,
                "after_scan_id": after,
            })
            .to_string(),
            ..Request::default()
        };
        self.comparison_report = Some("Comparing saved snapshots…".into());
        self.submit(RequestKind::CompareSnapshots, request)
    }

    fn start_operation(&mut self) -> Task<Message> {
        if self.job.is_some() {
            return Task::none();
        }
        let request = Request {
            operation: self.selected_operation.clone(),
            input: selected_or_typed(self.input_selection.as_ref(), &self.input_path),
            output: selected_or_typed(self.output_selection.as_ref(), &self.output_path),
            parameter: self.parameter.clone(),
            ..Request::default()
        };
        self.submit(RequestKind::Operation, request)
    }

    fn submit(&mut self, kind: RequestKind, request: Request) -> Task<Message> {
        let job = Job::new();
        self.job = Some(job.clone());
        self.job_kind = Some(kind);
        self.status = format!("{} running…", request_title(kind));
        let handler = self.handler;
        let (sender, receiver) = oneshot::channel();
        if let Err(error) = std::thread::Builder::new()
            .name("file-studio-workspace".into())
            .spawn(move || {
                let _ = sender.send(handler(request, job));
            })
        {
            self.job = None;
            self.job_kind = None;
            self.status = format!("Could not start operation: {error}");
            return Task::none();
        }
        Task::perform(
            async move {
                receiver.await.unwrap_or_else(|_| {
                    Err(Error::new(
                        ErrorKind::Internal,
                        "The background operation stopped unexpectedly",
                    ))
                })
            },
            move |result| Message::RequestFinished(kind, result),
        )
    }

    fn finish_request(&mut self, kind: RequestKind, outcome: Outcome) -> Task<Message> {
        match kind {
            RequestKind::CreateCatalogue => {
                let Some(path) = outcome.written else {
                    self.status = "Catalogue creation finished without an output path.".into();
                    return Task::none();
                };
                self.catalogue_path = path.to_string_lossy().into_owned();
                self.catalogue_selection = Some(path);
                self.search_results = None;
                self.search_table = None;
                self.history.clear();
                self.history_table_rows.clear();
                self.history_table = None;
                self.history_truncated = false;
                self.inspection_path = None;
                self.inspection_catalogued_bytes = None;
                self.inspection_report = None;
                self.search_table_state = TableState::new(50);
                self.history_table_state = TableState::new(20);
                self.status = "Catalogue created. Loading the first scan snapshot…".into();
                return self.start_history();
            }
            RequestKind::BackupCatalogue => {
                let path = outcome
                    .written
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "(no output path)".into());
                let report = serde_json::from_str::<serde_json::Value>(&outcome.preview).ok();
                let digest = report
                    .as_ref()
                    .and_then(|report| report["sha256"].as_str())
                    .unwrap_or("unavailable");
                self.status = format!(
                    "Catalogue backup created at {path}. SQLite integrity passed; SHA-256 {digest}."
                );
            }
            RequestKind::Search => match SearchReport::parse(&outcome.preview) {
                Ok(report) => {
                    self.status = format!(
                        "Found {} of {} saved paths. Source storage is not accessed by search.",
                        report.matched_files, report.catalogued_files
                    );
                    self.search_table_state = TableState::new(50);
                    match search_table_model(&report.files) {
                        Ok(table) => {
                            self.search_table = Some(table);
                            self.search_results = Some(report);
                        }
                        Err(error) => {
                            self.search_table = None;
                            self.search_results = None;
                            self.status = format!("Could not display search results: {error}");
                        }
                    }
                }
                Err(error) => {
                    self.search_table = None;
                    self.search_results = None;
                    self.status = format!("Could not display search results: {error}");
                }
            },
            RequestKind::Duplicates => match DuplicateReport::parse(&outcome.preview) {
                Ok(report) => {
                    self.duplicate_page_index = 0;
                    self.status = format!(
                        "Scanned {} files; found {} groups with matching content hashes. No files were modified.",
                        report.regular_files_scanned,
                        report.groups.len()
                    );
                    self.duplicate_report = Some(report);
                }
                Err(error) => {
                    self.duplicate_report = None;
                    self.status = format!("Could not display duplicate candidates: {error}");
                }
            },
            RequestKind::Usage => match DirectoryUsageReport::parse(&outcome.preview) {
                Ok(report) => {
                    self.status = format!(
                        "Analyzed {} regular files totaling {}. Filesystem contents were read only.",
                        report.regular_files,
                        format_bytes(report.total_bytes.into())
                    );
                    self.usage_report = Some(report);
                }
                Err(error) => {
                    self.usage_report = None;
                    self.status = format!("Could not display directory usage: {error}");
                }
            },
            RequestKind::History => match HistoryReport::parse(&outcome.preview) {
                Ok(report) => {
                    self.history = report.scans;
                    self.history_truncated = report.truncated;
                    self.history_table_rows = self.history.clone();
                    self.history_table_state = TableState::new(20);
                    match history_table_model(&self.history_table_rows) {
                        Ok(table) => {
                            self.history_table = Some(table);
                            self.status =
                                format!("Loaded {} recent scan snapshots.", self.history.len());
                        }
                        Err(error) => {
                            self.history_table = None;
                            self.status = format!("Could not display scan history: {error}");
                        }
                    }
                }
                Err(error) => {
                    self.history_table = None;
                    self.status = format!("Could not display scan history: {error}");
                }
            },
            RequestKind::CompareSnapshots => {
                let mut preview = outcome.preview;
                for warning in outcome.warnings {
                    preview.push_str(&format!("\nWarning: {warning}"));
                }
                self.comparison_report = Some(preview);
                self.status = "Compared retained snapshots using saved catalogue data only.".into();
            }
            RequestKind::Refresh => {
                self.inspection_path = None;
                self.inspection_catalogued_bytes = None;
                self.inspection_report = None;
                self.search_results = None;
                self.search_table = None;
                if outcome.written.is_none() {
                    self.status = "Partial directory scan: catalogue was not updated, and previous scan history was preserved.".into();
                    let mut preview = outcome.preview;
                    for warning in outcome.warnings {
                        preview.push_str(&format!("\nWarning: {warning}"));
                    }
                    self.comparison_report = Some(preview);
                    return Task::none();
                }
                self.status = match serde_json::from_str::<serde_json::Value>(&outcome.preview) {
                    Ok(report) if report["comparison_mode"] == "same-source" => format!(
                        "Saved scan {}: {} files, {} total bytes; {} added, {} changed, {} removed. Refreshing history…",
                        report["scan_id"].as_i64().unwrap_or_default(),
                        report["files"].as_u64().unwrap_or_default(),
                        report["total_bytes"].as_str().unwrap_or("unknown"),
                        report["added"].as_u64().unwrap_or_default(),
                        report["changed"].as_u64().unwrap_or_default(),
                        report["removed"].as_u64().unwrap_or_default(),
                    ),
                    Ok(report) => format!(
                        "Saved full-rescan baseline {}: {} files. Source identity changed or is unavailable; no cross-source deltas were inferred. Refreshing history…",
                        report["scan_id"].as_i64().unwrap_or_default(),
                        report["files"].as_u64().unwrap_or_default(),
                    ),
                    Err(_) => "Catalogue refresh finished; refreshing scan history…".into(),
                };
                return self.start_history();
            }
            RequestKind::InspectSelection => {
                let current_bytes = serde_json::from_str::<serde_json::Value>(&outcome.preview)
                    .ok()
                    .and_then(|report| report["bytes"].as_u64());
                let size_differs = self
                    .inspection_catalogued_bytes
                    .zip(current_bytes)
                    .is_some_and(|(saved, current)| saved != current);
                let mut preview = outcome.preview;
                for warning in outcome.warnings {
                    preview.push_str(&format!("\nWarning: {warning}"));
                }
                self.inspection_report = Some(preview);
                self.status = if size_differs {
                    "Read-only inspection completed; current size differs from the saved catalogue snapshot.".into()
                } else {
                    "Read-only inspection completed; the selected file was not modified.".into()
                };
            }
            RequestKind::Operation => {
                self.status = outcome.written.map_or_else(
                    || "Operation finished.".into(),
                    |path| format!("Wrote {}", path.display()),
                );
                self.operation_preview = outcome.preview;
                for warning in outcome.warnings {
                    self.operation_preview
                        .push_str(&format!("\nWarning: {warning}"));
                }
            }
        }
        Task::none()
    }

    fn duplicate_page_count(&self) -> usize {
        self.duplicate_report.as_ref().map_or(0, |report| {
            report.groups.len().div_ceil(DUPLICATE_PAGE_SIZE)
        })
    }

    fn save_preferences(&mut self) {
        if self.settings_unwritable {
            self.preferences_error = Some(
                "Appearance changes are session-only because preferences could not be read.".into(),
            );
            return;
        }
        let Some(path) = &self.preferences_path else {
            return;
        };
        self.preferences_error = self
            .preferences
            .save(path)
            .err()
            .map(|error| format!("Could not save workbench preferences: {error}"));
    }

    fn theme(&self) -> Theme {
        let preset = THEMES
            .iter()
            .find(|preset| preset.0 == self.preferences.theme)
            .unwrap_or(&THEMES[0]);
        let color = |rgb: [u8; 3]| Color::from_rgb8(rgb[0], rgb[1], rgb[2]);
        Theme::custom(
            preset.0.to_owned(),
            Palette {
                background: color(preset.1),
                text: color(preset.2),
                primary: color(preset.3),
                success: Color::from_rgb8(30, 140, 80),
                danger: Color::from_rgb8(200, 50, 50),
            },
        )
    }

    fn view(&self) -> Element<'_, Message> {
        let theme_options = THEMES
            .iter()
            .map(|preset| preset.0.to_owned())
            .collect::<Vec<_>>();
        let title = row![
            text("File Studio").size(24),
            button("Catalogue").on_press(Message::Page(Page::Catalogue)),
            button("Operations").on_press(Message::Page(Page::Operations)),
            button("Cancel current job")
                .on_press_maybe(self.job.is_some().then_some(Message::Cancel)),
            text("Theme"),
            pick_list(
                theme_options,
                Some(self.preferences.theme.clone()),
                Message::Theme
            ),
            text("Scale"),
            pick_list(
                SCALES.to_vec(),
                Some(self.preferences.scale),
                Message::Scale
            ),
        ]
        .spacing(12)
        .align_y(iced::Alignment::Center)
        .wrap();
        let body = match self.page {
            Page::Catalogue => self.catalogue_view(),
            Page::Operations => self.operations_view(),
        };
        let mut status = self.status.clone();
        if let Some(error) = &self.preferences_error {
            status.push('\n');
            status.push_str(error);
        }
        let progress: Element<'_, Message> = match (self.job.as_ref(), self.job_kind) {
            (Some(job), Some(kind)) => {
                let presentation = progress_presentation(kind, job.fraction());
                match presentation.fraction {
                    Some(fraction) => column![
                        text(presentation.label),
                        progress_bar(0.0..=1.0, fraction).width(Length::Fill),
                    ]
                    .spacing(4)
                    .into(),
                    None => text(presentation.label).into(),
                }
            }
            _ => text("").into(),
        };
        container(
            column![
                title,
                text(status).wrapping(text::Wrapping::WordOrGlyph),
                progress,
                body
            ]
            .spacing(12)
            .padding(12),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn catalogue_view(&self) -> Element<'_, Message> {
        let create_row = row![
            text("New catalogue"),
            text("Create a read-only scan snapshot from the selected source folder."),
            button("Create catalogue…").on_press_maybe(
                (self.job.is_none() && !self.root_path.trim().is_empty())
                    .then_some(Message::CreateCatalogue)
            ),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center)
        .wrap();
        let open_row = row![
            text("Saved catalogue"),
            text_input(
                "Path to a File Studio .sqlite catalogue",
                &self.catalogue_path
            )
            .on_input(Message::CataloguePath)
            .width(Length::Fill),
            button("Browse…").on_press(Message::BrowseCatalogue),
            button("Load history").on_press_maybe(
                (self.job.is_none() && !self.catalogue_path.trim().is_empty())
                    .then_some(Message::LoadHistory)
            ),
            button("Back up…").on_press_maybe(
                (self.job.is_none() && !self.catalogue_path.trim().is_empty())
                    .then_some(Message::BackupCatalogue)
            ),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center)
        .wrap();
        let search_row = row![
            text("Find paths"),
            text_input("Enter a filename or path fragment", &self.query)
                .on_input(Message::Query)
                .width(Length::Fill),
            button("Search").on_press_maybe(
                (self.job.is_none()
                    && !self.catalogue_path.trim().is_empty()
                    && !self.query.trim().is_empty())
                .then_some(Message::Search)
            ),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center)
        .wrap();
        let refresh_row = row![
            text("Source folder"),
            text_input(
                "Choose this folder to refresh or inspect a saved result",
                &self.root_path
            )
            .on_input(Message::RootPath)
            .width(Length::Fill),
            button("Choose folder…").on_press(Message::BrowseRoot),
            button("Add scan snapshot").on_press_maybe(
                (self.job.is_none()
                    && !self.catalogue_path.trim().is_empty()
                    && !self.root_path.trim().is_empty())
                .then_some(Message::Refresh)
            ),
            button("Analyze directory usage").on_press_maybe(
                (self.job.is_none() && !self.root_path.trim().is_empty())
                    .then_some(Message::AnalyzeUsage)
            ),
            button("Find duplicate candidates").on_press_maybe(
                (self.job.is_none() && !self.root_path.trim().is_empty())
                    .then_some(Message::FindDuplicates)
            ),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center)
        .wrap();

        let usage_view: Element<'_, Message> = if let Some(report) = &self.usage_report {
            let mut entries = report
                .directories
                .iter()
                .map(|(name, bytes)| (name.clone(), *bytes))
                .collect::<Vec<_>>();
            if report.root_bytes > 0 {
                entries.push(("(files in selected root)".into(), report.root_bytes));
            }
            entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            let mut chart = column![
                text("Directory usage by top-level folder").size(20),
                text(format!(
                    "{} regular files · {} total · bars show each share of the total",
                    report.regular_files,
                    format_bytes(report.total_bytes.into())
                )),
            ]
            .spacing(6);
            if entries.is_empty() {
                chart = chart.push(text("The selected folder contains no regular files."));
            }
            for (name, bytes) in entries.iter().take(20) {
                let fraction = usage_fraction(*bytes, report.total_bytes);
                chart = chart.push(
                    column![
                        row![
                            text(display_path(name)).width(Length::Fill),
                            text(format!(
                                "{} · {:.1}%",
                                format_bytes((*bytes).into()),
                                fraction * 100.0
                            )),
                        ]
                        .spacing(8),
                        progress_bar(0.0..=1.0, fraction),
                    ]
                    .spacing(3),
                );
            }
            if entries.len() > 20 {
                chart = chart.push(text(format!(
                    "Showing the 20 largest groups; {} more omitted from the preview.",
                    entries.len() - 20
                )));
            }
            scrollable(chart).height(Length::Fixed(260.0)).into()
        } else {
            column![
                text("Directory usage").size(20),
                text("Choose a source folder and analyze its top-level file sizes.")
            ]
            .spacing(6)
            .into()
        };

        let result_table: Element<'_, Message> = match (&self.search_results, &self.search_table) {
            (Some(results), Some(_)) if results.files.is_empty() => column![
                text("Search results").size(20),
                text("No saved paths matched this search.")
            ]
            .spacing(6)
            .into(),
            (Some(results), Some(table)) => {
                let inspect_selected = self
                    .search_table_state
                    .selected_row()
                    .and_then(|row| results.files.get(row))
                    .filter(|_| self.job.is_none() && !self.root_path.trim().is_empty())
                    .map(|entry| Message::InspectCatalogueFile(entry.path.clone()));
                column![
                    text("Search results").size(20),
                    text("Choose a row to select it, then inspect the selected file when its source folder is available."),
                    paginated_table(table, &self.search_table_state, Message::SearchTableAction),
                    button("Inspect selected file").on_press_maybe(inspect_selected),
                ]
                .spacing(6)
                .into()
            }
            _ => column![
                text("Search results").size(20),
                text("Search a saved catalogue to browse matching paths.")
            ]
            .spacing(6)
            .into(),
        };

        let mut inspector = column![
            text("Selected file properties, metadata and integrity").size(20),
            text("Search uses saved catalogue data only. Choose the source folder above and click Inspect to read a matched file; this does not modify the file."),
        ]
        .spacing(6);
        if let Some(path) = &self.inspection_path {
            inspector = inspector.push(text(format!("Selected path: {}", display_path(path))));
        }

        let mut duplicate_view = column![
            text("Duplicate candidates").size(20),
            text("The selected source folder is scanned and files with matching BLAKE3 content hashes are grouped for review. Hashing is capped at 1 GiB of candidate data. This is read-only; no files are deleted or moved."),
        ]
        .spacing(6);
        if let Some(report) = &self.duplicate_report {
            if report.groups.is_empty() {
                duplicate_view = duplicate_view.push(text(format!(
                    "No matching content-hash groups among {} regular files.",
                    report.regular_files_scanned
                )));
            }
            let start = self.duplicate_page_index * DUPLICATE_PAGE_SIZE;
            let end = (start + DUPLICATE_PAGE_SIZE).min(report.groups.len());
            for group in report.groups.iter().skip(start).take(DUPLICATE_PAGE_SIZE) {
                let mut group_view = column![text(format!(
                    "{} files · {} each · BLAKE3 {}",
                    group.paths.len(),
                    format_bytes(group.bytes_per_file.into()),
                    group.blake3
                ))
                .wrapping(text::Wrapping::WordOrGlyph)]
                .spacing(4);
                for path in group.paths.iter().take(8) {
                    group_view = group_view
                        .push(text(display_path(path)).wrapping(text::Wrapping::WordOrGlyph));
                }
                if group.paths.len() > 8 {
                    group_view = group_view
                        .push(text(format!("… and {} more paths", group.paths.len() - 8)));
                }
                duplicate_view =
                    duplicate_view.push(container(group_view).padding(8).width(Length::Fill));
            }
            if report.groups.len() > DUPLICATE_PAGE_SIZE {
                duplicate_view = duplicate_view.push(
                    row![
                        button("Previous groups").on_press_maybe(
                            (self.duplicate_page_index > 0)
                                .then_some(Message::PreviousDuplicatePage)
                        ),
                        text(format!(
                            "Showing groups {}–{} of {}",
                            start + 1,
                            end,
                            report.groups.len()
                        )),
                        button("Next groups").on_press_maybe(
                            (end < report.groups.len()).then_some(Message::NextDuplicatePage)
                        ),
                    ]
                    .spacing(8),
                );
            }
        } else {
            duplicate_view = duplicate_view.push(text(
                "Choose a source folder and run the duplicate candidate scan to review matching hashes.",
            ));
        }
        if let Some(bytes) = self.inspection_catalogued_bytes {
            inspector = inspector.push(text(format!(
                "Saved catalogue size: {}",
                format_bytes(bytes.into())
            )));
        }
        if let Some(report) = &self.inspection_report {
            inspector = inspector.push(
                container(text(report).wrapping(text::Wrapping::WordOrGlyph))
                    .padding(8)
                    .width(Length::Fill),
            );
        }

        let history_table: Element<'_, Message> = match &self.history_table {
            Some(_) if self.history_table_rows.is_empty() => column![
                text("Scan history").size(20),
                text("No scan history is available in this catalogue.")
            ]
            .spacing(6)
            .into(),
            Some(table) => {
                let mut history_view = column![
                    text("Scan history").size(20),
                    text("Select one row to fill the earlier scan ID and a second row to fill the later ID. Click a column heading to sort."),
                    paginated_table(table, &self.history_table_state, Message::HistoryTableAction),
                ]
                .spacing(6);
                if self.history_truncated {
                    history_view = history_view.push(text("Showing the latest 100 snapshots."));
                }
                history_view.into()
            }
            None => column![
                text("Scan history").size(20),
                text("Load history from a saved SQLite catalogue.")
            ]
            .spacing(6)
            .into(),
        };

        let comparison = column![
            text("Compare saved snapshots").size(20),
            text("Enter two scan IDs from the history table. The comparison reads only the local catalogue and reports whether both scans share a stable source identity."),
            row![
                text_input("Earlier scan ID", &self.compare_before)
                    .on_input(Message::CompareBefore)
                    .width(Length::Fixed(160.0)),
                text_input("Later scan ID", &self.compare_after)
                    .on_input(Message::CompareAfter)
                    .width(Length::Fixed(160.0)),
                button("Compare snapshots").on_press_maybe(
                    (self.job.is_none()
                        && !self.compare_before.trim().is_empty()
                        && !self.compare_after.trim().is_empty())
                    .then_some(Message::CompareSnapshots)
                ),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center)
            .wrap(),
        ]
        .spacing(8);
        let comparison = if let Some(report) = &self.comparison_report {
            comparison.push(
                container(text(report).wrapping(text::Wrapping::WordOrGlyph))
                    .padding(8)
                    .width(Length::Fill),
            )
        } else {
            comparison.push(text("No snapshot comparison has been run."))
        };

        scrollable(
            column![
                text("Offline file catalogue").size(22),
                text("Search stored paths while a drive is disconnected. Search reads the saved catalogue only; it does not open files on the original drive."),
                open_row,
                search_row,
                refresh_row,
                create_row,
                result_table,
                usage_view,
                inspector,
                duplicate_view,
                history_table,
                comparison,
            ]
            .spacing(12),
        )
        .height(Length::Fill)
        .into()
    }

    fn operations_view(&self) -> Element<'_, Message> {
        let operations = self
            .operations
            .iter()
            .map(OperationChoice)
            .collect::<Vec<_>>();
        let selected = operations
            .iter()
            .copied()
            .find(|choice| choice.0.id == self.selected_operation);
        let hint = selected.map_or("", |choice| choice.0.hint);
        let mut run = button("Run operation");
        if self.job.is_none() && selected.is_some() {
            run = run.on_press(Message::RunOperation);
        }
        scrollable(
            column![
                text("Processing operations").size(22),
                text("The same tested File Studio routes are available here and to the CLI."),
                text("Operations write only to new output paths; existing files are not replaced. A SQLite scan catalogue must be outside the source folder."),
                row![
                    text("Operation"),
                    pick_list(operations, selected, |choice| Message::Operation(
                        choice.0.id.to_owned()
                    ))
                ]
                .spacing(8),
                text(hint).wrapping(text::Wrapping::WordOrGlyph),
                text("Input path"),
                row![
                    text_input("File or folder path", &self.input_path)
                        .on_input(Message::Input)
                        .width(Length::Fill),
                    button("File…").on_press(Message::BrowseInputFile),
                    button("Folder…").on_press(Message::BrowseInputFolder),
                ]
                .spacing(8)
                .wrap(),
                text("New output path (if required)"),
                row![
                    text_input("Output path", &self.output_path)
                        .on_input(Message::Output)
                        .width(Length::Fill),
                    button("Save as…").on_press(Message::BrowseOutput),
                ]
                .spacing(8)
                .wrap(),
                text("Operation parameter"),
                text_input("See operation description", &self.parameter)
                    .on_input(Message::Parameter),
                row![run].spacing(8),
                text("Result and warnings"),
                text(&self.operation_preview).wrapping(text::Wrapping::WordOrGlyph),
            ]
            .spacing(10),
        )
        .height(Length::Fill)
        .into()
    }
}

fn request_title(kind: RequestKind) -> &'static str {
    match kind {
        RequestKind::CreateCatalogue => "Catalogue creation",
        RequestKind::BackupCatalogue => "Catalogue backup",
        RequestKind::Search => "Catalogue search",
        RequestKind::History => "Scan history",
        RequestKind::Refresh => "Catalogue refresh",
        RequestKind::Usage => "Directory usage analysis",
        RequestKind::Duplicates => "Duplicate candidate scan",
        RequestKind::CompareSnapshots => "Snapshot comparison",
        RequestKind::InspectSelection => "Selected file inspection",
        RequestKind::Operation => "Operation",
    }
}

fn run(operations: &'static [Operation], handler: Handler) -> iced::Result {
    iced::application("File Studio", StudioUi::update, StudioUi::view)
        .theme(StudioUi::theme)
        .scale_factor(|state: &StudioUi| f64::from(state.preferences.scale) / 100.0)
        .subscription(StudioUi::subscription)
        .run_with(move || (StudioUi::new(operations, handler), Task::none()))
}

impl StudioUi {
    fn subscription(&self) -> Subscription<Message> {
        let keyboard = iced::keyboard::on_key_press(|key, modifiers| {
            Some(Message::KeyPressed(key, modifiers))
        });
        if self.job.is_some() {
            Subscription::batch([
                keyboard,
                iced::time::every(Duration::from_millis(100)).map(|_| Message::ProgressTick),
            ])
        } else {
            keyboard
        }
    }
}

pub fn run_app(operations: &'static [Operation], handler: Handler) -> iced::Result {
    run(operations, handler)
}

#[cfg(test)]
mod tests {
    use super::*;
    use file_studio::OPERATIONS;

    fn no_op(_: Request, _: Job) -> localwright_core::Result<Outcome> {
        Ok(Outcome::default())
    }

    #[test]
    fn workspace_starts_on_catalogue_and_pages_search_results() {
        let mut ui = StudioUi::new(OPERATIONS, no_op);
        assert_eq!(ui.page, Page::Catalogue);
        let report = SearchReport {
            schema_version: 1,
            catalogued_files: 205,
            matched_files: 205,
            files: (0..205)
                .map(|index| file_studio::catalogue_workspace::CatalogueFile {
                    path: format!("file-{index}"),
                    bytes: index,
                })
                .collect(),
        };
        ui.search_table = Some(search_table_model(&report.files).unwrap());
        ui.search_results = Some(report);
        let result_count = ui.search_results.as_ref().unwrap().files.len();
        assert_eq!(ui.search_table_state.page_count(result_count), 5);
        let _ = ui.update(Message::SearchTableAction(TableAction::PageChanged(3)));
        assert_eq!(ui.search_table_state.current_page(result_count), 3);
        let _ = ui.update(Message::SearchTableAction(TableAction::PageChanged(
            usize::MAX,
        )));
        assert_eq!(ui.search_table_state.current_page(result_count), 4);
        let _ = ui.update(Message::SearchTableAction(TableAction::SortBy {
            column: 1,
            direction: SortDirection::Descending,
        }));
        assert_eq!(ui.search_results.as_ref().unwrap().files[0].bytes, 204);
        let _ = ui.update(Message::SearchTableAction(TableAction::SelectRow(0)));
        assert_eq!(ui.search_table_state.selected_row(), Some(0));
        assert_eq!(
            ui.search_results.as_ref().unwrap().files[0].path,
            "file-204"
        );
    }

    #[test]
    fn catalogue_backup_completion_surfaces_integrity_and_digest() {
        let mut ui = StudioUi::new(OPERATIONS, no_op);
        let _ = ui.finish_request(
            RequestKind::BackupCatalogue,
            Outcome {
                preview: r#"{"integrity_check":"ok","sha256":"abc123"}"#.into(),
                written: Some(PathBuf::from("archive.sqlite")),
                ..Outcome::default()
            },
        );
        assert!(ui.status.contains("archive.sqlite"));
        assert!(ui.status.contains("integrity passed"));
        assert!(ui.status.contains("abc123"));
    }

    #[test]
    fn history_table_sorting_and_row_selection_feed_snapshot_comparison() {
        let mut ui = StudioUi::new(OPERATIONS, no_op);
        ui.history_table_rows = vec![
            ScanSummary {
                scan_id: 1,
                scanned_unix_ms: 100,
                root_label: "Research".into(),
                files: 4,
                total_bytes: "200".into(),
                comparison_mode: "baseline".into(),
                added: 0,
                changed: 0,
                removed: 0,
            },
            ScanSummary {
                scan_id: 2,
                scanned_unix_ms: 200,
                root_label: "Research".into(),
                files: 5,
                total_bytes: "100".into(),
                comparison_mode: "same-source".into(),
                added: 1,
                changed: 0,
                removed: 0,
            },
        ];
        ui.history_table = Some(history_table_model(&ui.history_table_rows).unwrap());
        let _ = ui.update(Message::HistoryTableAction(TableAction::SortBy {
            column: 2,
            direction: SortDirection::Ascending,
        }));
        assert_eq!(ui.history_table_rows[0].scan_id, 2);
        let _ = ui.update(Message::HistoryTableAction(TableAction::SelectRow(0)));
        assert_eq!(ui.compare_before, "2");
        let _ = ui.update(Message::HistoryTableAction(TableAction::SelectRow(1)));
        assert_eq!(ui.compare_after, "1");
    }

    #[test]
    fn catalogue_routes_require_inputs_before_dispatch() {
        let mut ui = StudioUi::new(OPERATIONS, no_op);
        let _ = ui.update(Message::Search);
        assert!(ui.job.is_none());
        assert!(ui.status.contains("Choose a saved catalogue"));
        let _ = ui.update(Message::Refresh);
        assert!(ui.job.is_none());
        assert!(ui.status.contains("Choose an existing SQLite catalogue"));
        let _ = ui.update(Message::FindDuplicates);
        assert!(ui.job.is_none());
        assert!(ui
            .status
            .contains("Choose the source folder before checking duplicate candidates"));
        let _ = ui.update(Message::InspectCatalogueFile("report.txt".into()));
        assert!(ui.job.is_none());
        assert!(ui.status.contains("Choose the source folder"));
        let _ = ui.update(Message::CreateCatalogue);
        assert!(ui.job.is_none());
        assert!(ui
            .status
            .contains("Choose the source folder before creating"));
    }

    #[test]
    fn duplicate_candidate_groups_are_bounded_and_pageable() {
        let mut ui = StudioUi::new(OPERATIONS, no_op);
        ui.duplicate_report = Some(DuplicateReport {
            schema_version: 1,
            regular_files_scanned: 50,
            groups: (0..25)
                .map(|index| file_studio::catalogue_workspace::DuplicateGroup {
                    bytes_per_file: index,
                    blake3: "a".repeat(64),
                    paths: vec![format!("file-{index}-a"), format!("file-{index}-b")],
                })
                .collect(),
        });
        assert_eq!(ui.duplicate_page_count(), 2);
        let _ = ui.update(Message::NextDuplicatePage);
        assert_eq!(ui.duplicate_page_index, 1);
        let _ = ui.update(Message::NextDuplicatePage);
        assert_eq!(ui.duplicate_page_index, 1);
        let _ = ui.update(Message::PreviousDuplicatePage);
        assert_eq!(ui.duplicate_page_index, 0);
    }

    #[cfg(unix)]
    #[test]
    fn file_dialog_selection_preserves_non_unicode_path_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let selected = PathBuf::from(std::ffi::OsString::from_vec(
            b"catalogue-\xff.sqlite".to_vec(),
        ));
        let display = selected.to_string_lossy().into_owned();
        assert_ne!(PathBuf::from(&display), selected);
        assert_eq!(selected_or_typed(Some(&selected), &display), selected);
        assert_eq!(
            selected_or_typed(None, "typed.sqlite"),
            PathBuf::from("typed.sqlite")
        );
    }

    #[test]
    fn settings_keep_shared_theme_and_shortcut_compatibility() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("workbench.json");
        let preferences = Preferences::default();
        preferences.save(&path).unwrap();
        assert_eq!(Preferences::load(&path).unwrap().theme, "Modern Light");
        fs::write(
            &path,
            br#"{"schema_version":1,"theme":"Modern Dark","scale":125,"shortcuts":{"bindings":{"run":{"key":"enter","command":true,"shift":false,"alt":false},"cancel":{"key":"escape","command":false,"shift":false,"alt":false}}}}"#,
        )
        .unwrap();
        let before = Preferences::load(&path).unwrap();
        assert_eq!(before.theme, "Modern Dark");
        assert!(before.shortcuts.is_some());
        before.save(&path).unwrap();
        assert!(Preferences::load(&path).unwrap().shortcuts.is_some());
        let mut old_style = serde_json::to_value(&preferences).unwrap();
        old_style.as_object_mut().unwrap().remove("shortcuts");
        fs::write(&path, serde_json::to_vec(&old_style).unwrap()).unwrap();
        assert_eq!(Preferences::load(&path).unwrap().shortcuts, None);
    }

    #[test]
    fn search_query_has_a_bounded_input_size() {
        let mut ui = StudioUi::new(OPERATIONS, no_op);
        ui.catalogue_path = "catalog.sqlite".into();
        ui.query = "x".repeat(4097);
        let _ = ui.update(Message::Search);
        assert!(ui.job.is_none());
        assert!(ui.status.contains("at most 4 KiB"));
    }

    #[test]
    fn progress_model_distinguishes_unknown_scan_from_snapshot_indexing() {
        let scanning = progress_presentation(RequestKind::Refresh, None);
        assert!(scanning.label.contains("indeterminate"));
        assert_eq!(scanning.fraction, None);

        let creating = progress_presentation(RequestKind::CreateCatalogue, None);
        assert_eq!(creating.label, scanning.label);
        assert_eq!(creating.fraction, None);

        let indexing = progress_presentation(RequestKind::Refresh, Some(0.4));
        assert!(indexing.label.contains("40%"));
        assert_eq!(indexing.fraction, Some(0.4));
    }

    #[test]
    fn catalogue_creation_accepts_only_sqlite_outputs() {
        assert!(is_sqlite_catalogue_path(Path::new("/tmp/index.sqlite")));
        assert!(is_sqlite_catalogue_path(Path::new("/tmp/index.SQLITE3")));
        assert!(!is_sqlite_catalogue_path(Path::new("/tmp/index.csv")));
        assert!(!is_sqlite_catalogue_path(Path::new("/tmp/index")));
    }
}
