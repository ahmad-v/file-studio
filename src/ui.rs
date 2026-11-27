#![forbid(unsafe_code)]

use file_studio::catalogue_workspace::{display_path, format_bytes, HistoryReport, SearchReport};
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
use localwright_ui::THEMES;
use serde::{Deserialize, Serialize};
use std::{
    env, fmt, fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

const SCALES: [u16; 7] = [80, 100, 125, 150, 200, 250, 300];
const PAGE_SIZE: usize = 100;

fn selected_or_typed(selected: Option<&PathBuf>, typed: &str) -> PathBuf {
    selected.cloned().unwrap_or_else(|| PathBuf::from(typed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Catalogue,
    Operations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Search,
    History,
    Refresh,
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
        (RequestKind::Refresh, None) => ProgressPresentation {
            label: "Scanning folder; progress is indeterminate.".into(),
            fraction: None,
        },
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
    history: Vec<file_studio::catalogue_workspace::ScanSummary>,
    history_truncated: bool,
    inspection_path: Option<String>,
    inspection_catalogued_bytes: Option<u64>,
    inspection_report: Option<String>,
    page_index: usize,
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
    CataloguePicked(Option<PathBuf>),
    BrowseRoot,
    RootPicked(Option<PathBuf>),
    Search,
    LoadHistory,
    Refresh,
    InspectCatalogueFile(String),
    PreviousPage,
    NextPage,
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
            history: Vec::new(),
            history_truncated: false,
            inspection_path: None,
            inspection_catalogued_bytes: None,
            inspection_report: None,
            page_index: 0,
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
                self.history.clear();
                self.inspection_path = None;
                self.inspection_catalogued_bytes = None;
                self.inspection_report = None;
                self.page_index = 0;
                self.status =
                    "Select a saved catalogue, then search paths or load its history.".into();
            }
            Message::RootPath(path) => {
                self.root_path = path;
                self.root_selection = None;
                self.inspection_path = None;
                self.inspection_catalogued_bytes = None;
                self.inspection_report = None;
            }
            Message::Query(query) => {
                self.query = query;
                self.search_results = None;
                self.page_index = 0;
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
            Message::CataloguePicked(path) => {
                if let Some(path) = path {
                    self.catalogue_path = path.to_string_lossy().into_owned();
                    self.catalogue_selection = Some(path);
                    self.search_results = None;
                    self.history.clear();
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
                    self.inspection_path = None;
                    self.inspection_catalogued_bytes = None;
                    self.inspection_report = None;
                }
            }
            Message::Search => return self.start_search(),
            Message::LoadHistory => return self.start_history(),
            Message::Refresh => return self.start_refresh(),
            Message::InspectCatalogueFile(relative) => {
                return self.start_catalogue_inspection(relative)
            }
            Message::PreviousPage => self.page_index = self.page_index.saturating_sub(1),
            Message::NextPage => {
                if self.page_index + 1 < self.page_count() {
                    self.page_index += 1;
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
                            RequestKind::InspectSelection => {
                                self.inspection_report =
                                    Some(format!("Inspection failed: {}", error.message));
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
        self.page_index = 0;
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
        let request = Request {
            operation: "workspace-catalog-refresh".into(),
            input: selected_or_typed(self.root_selection.as_ref(), &self.root_path),
            output: selected_or_typed(self.catalogue_selection.as_ref(), &self.catalogue_path),
            ..Request::default()
        };
        self.submit(RequestKind::Refresh, request)
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
            RequestKind::Search => match SearchReport::parse(&outcome.preview) {
                Ok(report) => {
                    self.page_index = 0;
                    self.status = format!(
                        "Found {} of {} saved paths. Source storage is not accessed by search.",
                        report.matched_files, report.catalogued_files
                    );
                    self.search_results = Some(report);
                }
                Err(error) => self.status = format!("Could not display search results: {error}"),
            },
            RequestKind::History => match HistoryReport::parse(&outcome.preview) {
                Ok(report) => {
                    self.history = report.scans;
                    self.history_truncated = report.truncated;
                    self.status = format!("Loaded {} recent scan snapshots.", self.history.len());
                }
                Err(error) => self.status = format!("Could not display scan history: {error}"),
            },
            RequestKind::Refresh => {
                self.inspection_path = None;
                self.inspection_catalogued_bytes = None;
                self.inspection_report = None;
                self.search_results = None;
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

    fn page_count(&self) -> usize {
        self.search_results
            .as_ref()
            .map_or(0, |report| report.files.len().div_ceil(PAGE_SIZE))
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
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center)
        .wrap();

        let mut result_table = column![
            text("Search results").size(20),
            row![
                text("Relative path").width(Length::Fill),
                text("Size").width(Length::Fixed(120.0)),
                text("Action").width(Length::Fixed(90.0))
            ]
            .spacing(12),
        ]
        .spacing(6);
        if let Some(results) = &self.search_results {
            let start = self.page_index.saturating_mul(PAGE_SIZE);
            let end = (start + PAGE_SIZE).min(results.files.len());
            if results.files.is_empty() {
                result_table = result_table.push(text("No saved paths matched this search."));
            }
            for entry in results.files.iter().skip(start).take(PAGE_SIZE) {
                result_table = result_table.push(
                    row![
                        text(display_path(&entry.path))
                            .width(Length::Fill)
                            .wrapping(text::Wrapping::WordOrGlyph),
                        text(format_bytes(entry.bytes.into())).width(Length::Fixed(120.0)),
                        button("Inspect").on_press_maybe(
                            (self.job.is_none() && !self.root_path.trim().is_empty())
                                .then_some(Message::InspectCatalogueFile(entry.path.clone()))
                        ),
                    ]
                    .spacing(12),
                );
            }
            if results.files.len() > PAGE_SIZE {
                result_table = result_table.push(
                    row![
                        button("Previous")
                            .on_press_maybe((self.page_index > 0).then_some(Message::PreviousPage)),
                        text(format!(
                            "Showing {}–{} of {}",
                            start + 1,
                            end,
                            results.files.len()
                        )),
                        button("Next").on_press_maybe(
                            (end < results.files.len()).then_some(Message::NextPage)
                        ),
                    ]
                    .spacing(12),
                );
            }
        } else {
            result_table =
                result_table.push(text("Search a saved catalogue to browse matching paths."));
        }

        let mut inspector = column![
            text("Selected file properties, metadata and integrity").size(20),
            text("Search uses saved catalogue data only. Choose the source folder above and click Inspect to read a matched file; this does not modify the file."),
        ]
        .spacing(6);
        if let Some(path) = &self.inspection_path {
            inspector = inspector.push(text(format!("Selected path: {}", display_path(path))));
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

        let mut history_table = column![
            text("Scan history").size(20),
            row![
                text("Scan / source").width(Length::FillPortion(3)),
                text("Files").width(Length::Fixed(80.0)),
                text("Total size").width(Length::Fixed(120.0)),
                text("Refresh delta").width(Length::Fixed(190.0)),
                text("Timestamp (UTC ms)").width(Length::Fixed(180.0)),
            ]
            .spacing(8),
        ]
        .spacing(6);
        if self.history.is_empty() {
            history_table = history_table.push(text("No scan history loaded."));
        }
        for scan in &self.history {
            let size = scan
                .total_bytes
                .parse::<u128>()
                .map(format_bytes)
                .unwrap_or_else(|_| "unknown".into());
            history_table = history_table.push(
                row![
                    text(format!(
                        "#{} · {}",
                        scan.scan_id,
                        display_path(&scan.root_label)
                    ))
                    .width(Length::FillPortion(3)),
                    text(scan.files.to_string()).width(Length::Fixed(80.0)),
                    text(size).width(Length::Fixed(120.0)),
                    text(if scan.comparison_mode == "same-source" {
                        format!("+{} ~{} −{}", scan.added, scan.changed, scan.removed)
                    } else if scan.comparison_mode == "full-rescan" {
                        "Full rescan; identity changed/unknown".to_owned()
                    } else if scan.comparison_mode == "unknown" {
                        "Legacy snapshot; identity unknown".to_owned()
                    } else {
                        "Baseline".to_owned()
                    })
                    .width(Length::Fixed(190.0)),
                    text(scan.scanned_unix_ms.to_string()).width(Length::Fixed(180.0)),
                ]
                .spacing(8),
            );
        }
        if self.history_truncated {
            history_table = history_table.push(text("Showing the latest 100 snapshots."));
        }

        scrollable(
            column![
                text("Offline file catalogue").size(22),
                text("Search stored paths while a drive is disconnected. Search reads the saved catalogue only; it does not open files on the original drive."),
                open_row,
                search_row,
                refresh_row,
                result_table,
                inspector,
                history_table,
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

impl StudioUi {
    #[cfg(test)]
    fn page_count_for_test(&self) -> usize {
        self.page_count()
    }
}

fn request_title(kind: RequestKind) -> &'static str {
    match kind {
        RequestKind::Search => "Catalogue search",
        RequestKind::History => "Scan history",
        RequestKind::Refresh => "Catalogue refresh",
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
        ui.search_results = Some(SearchReport {
            schema_version: 1,
            catalogued_files: 205,
            matched_files: 205,
            files: (0..205)
                .map(|index| file_studio::catalogue_workspace::CatalogueFile {
                    path: format!("file-{index}"),
                    bytes: index,
                })
                .collect(),
        });
        assert_eq!(ui.page_count_for_test(), 3);
        let _ = ui.update(Message::NextPage);
        assert_eq!(ui.page_index, 1);
        let _ = ui.update(Message::NextPage);
        let _ = ui.update(Message::NextPage);
        assert_eq!(ui.page_index, 2);
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
        let _ = ui.update(Message::InspectCatalogueFile("report.txt".into()));
        assert!(ui.job.is_none());
        assert!(ui.status.contains("Choose the source folder"));
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

        let indexing = progress_presentation(RequestKind::Refresh, Some(0.4));
        assert!(indexing.label.contains("40%"));
        assert_eq!(indexing.fraction, Some(0.4));
    }
}
