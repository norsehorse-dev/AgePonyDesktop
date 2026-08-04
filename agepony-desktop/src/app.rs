//! The `App` struct: every piece of persistent UI state lives here.
//!
//! Immediate mode means [`App::ui`] runs top to bottom every frame and nothing
//! is retained between frames except these fields. There is no view identity,
//! no diffing, and no `@State`. If you want something to still be there next
//! frame, it goes in this struct.

use crate::panels;
use crate::tasks::Running;
use agepony_core::book::Book;
use agepony_core::store::{Kind, Store};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// Which destination the rail has selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Tab {
    /// Sealing and opening, one screen. The aliases absorb prefs persisted
    /// before Encrypt and Decrypt merged, so an upgrade keeps the user's other
    /// preferences instead of failing the whole blob back to defaults.
    #[default]
    #[serde(alias = "Encrypt", alias = "Decrypt")]
    Files,
    /// Identity management.
    Identities,
    /// The recipient book.
    Recipients,
}

impl Tab {
    pub(crate) const ALL: [Tab; 3] = [Tab::Files, Tab::Identities, Tab::Recipients];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Tab::Files => "Files",
            Tab::Identities => "Identities",
            Tab::Recipients => "Recipients",
        }
    }

    /// The rail glyph for this destination.
    pub(crate) const fn icon(self) -> char {
        match self {
            Tab::Files => crate::theme::icon::FILES,
            Tab::Identities => crate::theme::icon::KEY_ROUND,
            Tab::Recipients => crate::theme::icon::USERS,
        }
    }
}

/// What will happen to a queued file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAction {
    /// Encrypt it.
    Seal,
    /// Decrypt it.
    Open,
}

/// One file in the queue, and what has become of it.
pub struct QueuedFile {
    /// Where it is.
    pub path: PathBuf,
    /// Which group it landed in. Decided by reading the file's header, not its
    /// name — see [`agepony_core::decrypt::looks_like_age_file`].
    pub action: FileAction,
    /// Its size when it was queued, for the row's detail line.
    pub size: Option<u64>,
    /// `Ok(output)` once it has been written, `Err(why)` once it has failed,
    /// `None` while it is still waiting or running. Results are folded in here
    /// from the finished job, so a row keeps its answer after the job object
    /// is gone and a re-run knows to leave it alone.
    pub outcome: Option<Result<PathBuf, String>>,
}

/// Where the decrypt panel gets its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DecryptSource {
    /// The active identity from the store.
    #[default]
    Active,
    /// An identity file chosen at runtime.
    File,
    /// A passphrase-encrypted file, no identity involved.
    Passphrase,
}

/// Everything the Files screen remembers between frames.
#[derive(Default)]
pub struct FilesState {
    /// Every file that has been dropped or chosen, in arrival order.
    pub queue: Vec<QueuedFile>,

    // ---- sealing --------------------------------------------------------
    /// Names of the book entries that are ticked.
    pub picked: BTreeSet<String>,
    /// Recipients typed directly, one per line.
    pub extra: String,
    /// Use a passphrase instead of recipients.
    pub use_passphrase: bool,
    /// The sealing passphrase, held only while the screen is open.
    pub passphrase: String,
    /// ASCII armor the output.
    pub armor: bool,

    // ---- opening --------------------------------------------------------
    /// Where the identity comes from.
    pub source: DecryptSource,
    /// Identity files chosen when `source` is [`DecryptSource::File`].
    pub identity_files: Vec<PathBuf>,
    /// The file's passphrase, for [`DecryptSource::Passphrase`].
    pub open_passphrase: String,
    /// The passphrase that unlocks a protected identity file.
    pub identity_passphrase: String,

    // ---- in flight ------------------------------------------------------
    /// The sealing job, if one is running. Two jobs, not one: a mixed drop
    /// runs both groups, and neither should wait for the other.
    pub seal_job: Option<Running>,
    /// The opening job, if one is running.
    pub open_job: Option<Running>,
}

impl FilesState {
    /// Fold a finished job's results into the queue and return its summary.
    ///
    /// After this the rows own their outcomes and the job can be dropped,
    /// which is what lets "run again" know which rows are already settled.
    pub fn absorb(&mut self, job: Running) -> String {
        for done in &job.done {
            if let Some(row) = self.queue.iter_mut().find(|q| q.path == done.input) {
                row.outcome = Some(Ok(done.output.clone()));
            }
        }
        for (input, why) in &job.failed {
            if let Some(row) = self.queue.iter_mut().find(|q| &q.path == input) {
                row.outcome = Some(Err(why.clone()));
            }
        }
        job.summary()
    }

    /// A one-line caption for whichever job is mid-file, for the status strip.
    #[must_use]
    pub fn running_caption(&self) -> Option<String> {
        let caption = |job: &Running, verb: &str| {
            job.current.as_ref().map(|p| {
                let name = p.file_name().map_or_else(
                    || p.display().to_string(),
                    |n| n.to_string_lossy().into_owned(),
                );
                format!("{verb} {name}")
            })
        };
        self.seal_job
            .as_ref()
            .filter(|j| j.in_flight())
            .and_then(|j| caption(j, "Sealing"))
            .or_else(|| {
                self.open_job
                    .as_ref()
                    .filter(|j| j.in_flight())
                    .and_then(|j| caption(j, "Opening"))
            })
    }

    /// Whether either group is mid-run.
    #[must_use]
    pub fn busy(&self) -> bool {
        self.seal_job.as_ref().is_some_and(Running::in_flight)
            || self.open_job.as_ref().is_some_and(Running::in_flight)
    }
}

/// Transient state for the Identities panel.
#[derive(Default)]
pub struct IdentitiesUi {
    /// Label for the identity about to be created or imported.
    pub label: String,
    /// Protect the new identity with a passphrase.
    pub protect: bool,
    /// That passphrase.
    pub passphrase: String,
    /// Passphrase for unlocking a file being imported.
    pub import_passphrase: String,
    /// Id being renamed, and the text typed so far.
    pub renaming: Option<(String, String)>,
    /// Id pending deletion, and the confirmation text typed so far.
    pub deleting: Option<(String, String)>,
    /// Whether the porting QR code is on screen.
    pub show_qr: bool,
    /// Cached QR code, keyed by the recipient it encodes. Rebuilding a
    /// version-26 code every frame would be silly.
    pub qr: Option<(String, crate::qr::Rendered)>,
    /// An identity that arrived from another device, waiting to be named and
    /// installed.
    pub pending_port: Option<PendingPort>,
}

/// A ported identity held between arriving and being installed.
pub struct PendingPort {
    /// What was in the file.
    pub ported: agepony_core::porting::Ported,
    /// The label the user will store it under.
    pub label: String,
}

/// Transient state for the Recipients panel.
#[derive(Default)]
pub struct RecipientsUi {
    /// Search box contents.
    pub search: String,
    /// The name being edited, or `None` when adding.
    pub editing: Option<String>,
    /// Form fields.
    pub name: String,
    /// Form fields.
    pub recipient: String,
    /// Form fields.
    pub note: String,
    /// Whether the add/edit form is open.
    pub form_open: bool,
}

/// The handful of UI choices worth remembering between launches.
///
/// Deliberately small. Window geometry is eframe's job (`persist_window`), and
/// nothing here is secret — no passphrases, no file paths, no key material, so
/// the persisted blob is as boring as the recipient book.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Prefs {
    tab: Tab,
    armor: bool,
    decrypt_source: DecryptSource,
    show_qr: bool,
    #[serde(default)]
    theme: ThemeChoice,
}

/// Light, dark, or whatever the desktop is set to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ThemeChoice {
    /// Follow the OS. The default, and what most people expect.
    #[default]
    System,
    /// Always light.
    Light,
    /// Always dark.
    Dark,
}

impl ThemeChoice {
    /// Every choice, in the order the Settings screen will offer them.
    ///
    /// Nothing in the running UI reads this today: the rail's interim control
    /// cycles with [`Self::next`] because a three-way segmented control does
    /// not fit 96pt. The real control lands with the Settings destination, and
    /// the rail fit test reads this meanwhile, so it is checked rather than
    /// merely kept.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "the Settings destination consumes this")
    )]
    pub(crate) const ALL: [ThemeChoice; 3] =
        [ThemeChoice::System, ThemeChoice::Light, ThemeChoice::Dark];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            ThemeChoice::System => "Auto",
            ThemeChoice::Light => "Light",
            ThemeChoice::Dark => "Dark",
        }
    }

    /// The next choice in the cycle, for the rail's one-button control.
    pub(crate) const fn next(self) -> Self {
        match self {
            ThemeChoice::System => ThemeChoice::Light,
            ThemeChoice::Light => ThemeChoice::Dark,
            ThemeChoice::Dark => ThemeChoice::System,
        }
    }

    fn apply(self, ctx: &egui::Context) {
        ctx.set_theme(match self {
            ThemeChoice::System => egui::ThemePreference::System,
            ThemeChoice::Light => egui::ThemePreference::Light,
            ThemeChoice::Dark => egui::ThemePreference::Dark,
        });
    }
}

const PREFS_KEY: &str = "agepony-prefs";

/// The application.
pub struct App {
    /// Selected rail destination.
    pub tab: Tab,
    /// Files screen state.
    pub files: FilesState,
    /// Identities panel state.
    pub identities: IdentitiesUi,
    /// Recipients panel state.
    pub recipients: RecipientsUi,
    /// The identity store.
    pub store: Store,
    /// The recipient book.
    pub book: Book,
    /// Where the book is stored.
    pub book_path: PathBuf,
    /// Where everything is stored.
    pub config_dir: PathBuf,
    /// A message to show at the bottom of the window.
    pub status: Option<String>,
    /// Light, dark or follow the OS.
    pub theme: ThemeChoice,
    /// Set once the theme has been pushed into egui, so it is applied on the
    /// first frame rather than only when changed.
    theme_applied: bool,
}

impl App {
    /// Build the app, loading the store and book from the config directory.
    #[must_use]
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let prefs: Prefs = cc
            .storage
            .and_then(|s| eframe::get_value(s, PREFS_KEY))
            .unwrap_or_default();
        let config_dir = config_dir();
        let book_path = config_dir.join("recipients.json");

        let mut status = None;
        let book = Book::load(&book_path).unwrap_or_else(|e| {
            status = Some(format!("Could not load the recipient book: {e}"));
            Book::default()
        });
        let store = Store::open(&config_dir).unwrap_or_else(|e| {
            status = Some(format!("Could not open the identity store: {e}"));
            // An unreadable index must not take the whole app down, but it also
            // must not silently overwrite whatever is there. Opening a store
            // rooted at a scratch path keeps the app usable and leaves the real
            // index alone for the user to look at.
            Store::open(&config_dir.join("recovery")).unwrap_or_else(|_| {
                Store::open(std::path::Path::new(".")).unwrap_or_else(|_| unreachable!())
            })
        });

        // Bring the book into line with the store before the first frame. This
        // is what backfills recipients for identities generated before they
        // were linked, and what clears any whose key is gone.
        let mut book = book;
        match agepony_core::vault::reconcile(&store, &mut book) {
            Ok(s) if s.is_clean() => {}
            Ok(s) => {
                let mut parts = Vec::new();
                if s.added > 0 {
                    parts.push(format!("added {} of your own recipient(s)", s.added));
                }
                if s.removed > 0 {
                    parts.push(format!("dropped {} whose identity is gone", s.removed));
                }
                if s.updated > 0 {
                    parts.push(format!("refreshed {}", s.updated));
                }
                status = Some(format!("Recipient book updated: {}", parts.join(", ")));
                if let Err(e) = book.save(&book_path) {
                    status = Some(format!("Could not save the recipient book: {e}"));
                }
            }
            Err(e) => status = Some(format!("Could not reconcile the recipient book: {e}")),
        }

        Self {
            tab: prefs.tab,
            files: FilesState {
                armor: prefs.armor,
                source: prefs.decrypt_source,
                ..FilesState::default()
            },
            identities: IdentitiesUi {
                show_qr: prefs.show_qr,
                ..IdentitiesUi::default()
            },
            recipients: RecipientsUi::default(),
            store,
            book,
            book_path,
            config_dir,
            status,
            theme: prefs.theme,
            theme_applied: false,
        }
    }

    /// Save the recipient book, reporting failure in the status bar.
    pub fn save_book(&mut self) {
        if let Err(e) = self.book.save(&self.book_path) {
            self.status = Some(format!("Could not save the recipient book: {e}"));
        }
    }

    /// Set the status line from a fallible operation.
    pub fn report(&mut self, result: agepony_core::Result<String>) {
        self.status = Some(match result {
            Ok(msg) => msg,
            Err(e) => e.to_string(),
        });
    }
}

impl App {
    /// Route files dropped onto the window.
    ///
    /// Everything goes to Files, whichever screen is open, and each file is
    /// grouped by reading its header rather than trusting its name. There is
    /// no mode to be in first, which was the point of merging the two panels.
    fn handle_drops(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if dropped.is_empty() {
            return;
        }

        self.tab = Tab::Files;
        let added = crate::panels::files::add_paths(self, dropped);
        self.status = Some(match added {
            0 => "Those files are already in the queue".to_owned(),
            1 => "Added 1 file".to_owned(),
            n => format!("Added {n} files"),
        });
    }

    /// Keyboard shortcuts.
    ///
    /// `Modifiers::COMMAND` is Cmd on macOS and Ctrl elsewhere, so this is one
    /// set of bindings that reads correctly on all three platforms.
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        use egui::{Key, Modifiers};

        for (i, tab) in Tab::ALL.iter().enumerate() {
            let key = match i {
                0 => Key::Num1,
                1 => Key::Num2,
                _ => Key::Num3,
            };
            if ctx.input_mut(|inp| inp.consume_key(Modifiers::COMMAND, key)) {
                self.tab = *tab;
            }
        }

        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::O)) {
            self.choose_files();
        }

        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::Enter))
            && self.tab == Tab::Files
        {
            crate::panels::files::run_all(self, ctx.clone());
        }

        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) {
            self.escape();
        }
    }

    /// One dialog, no filters: the probe decides what each file is, so there
    /// is no wrong dialog to have opened.
    pub(crate) fn choose_files(&mut self) {
        if let Some(files) = rfd::FileDialog::new().pick_files() {
            self.tab = Tab::Files;
            let added = crate::panels::files::add_paths(self, files);
            if added > 0 {
                self.status = None;
            }
        }
    }

    /// Escape: back out of whatever is open, innermost first.
    fn escape(&mut self) {
        let mut cancelled = false;
        for job in [self.files.seal_job.as_ref(), self.files.open_job.as_ref()]
            .into_iter()
            .flatten()
            .filter(|j| j.in_flight())
        {
            job.cancel();
            cancelled = true;
        }
        if cancelled {
            return;
        }
        if self.identities.pending_port.is_some() {
            self.identities.pending_port = None;
            return;
        }
        if self.identities.deleting.is_some() {
            self.identities.deleting = None;
            return;
        }
        if self.identities.renaming.is_some() {
            self.identities.renaming = None;
            return;
        }
        if self.recipients.form_open {
            self.recipients.form_open = false;
            self.recipients.editing = None;
            return;
        }
        self.status = None;
    }

    /// A translucent overlay while files are held over the window.
    fn drop_hint(&self, ctx: &egui::Context) {
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        if !hovering {
            return;
        }

        let layer = egui::LayerId::new(egui::Order::Foreground, egui::Id::new("drop-hint"));
        let painter = ctx.layer_painter(layer);
        let rect = ctx.viewport_rect();
        painter.rect_filled(rect, 0.0, egui::Color32::from_black_alpha(170));

        // The shield, filled with the brand gradient. This is the one moment in
        // the app where the mark gets to be the whole interface.
        let side = (rect.height() * 0.34).clamp(120.0, 260.0);
        let shield = egui::Rect::from_center_size(
            rect.center() - egui::vec2(0.0, side * 0.14),
            egui::Vec2::splat(side),
        );
        crate::theme::draw_gradient_mark(&painter, shield);

        painter.text(
            egui::pos2(rect.center().x, shield.bottom() + 26.0),
            egui::Align2::CENTER_CENTER,
            "Drop files here",
            crate::theme::semibold(22.0),
            egui::Color32::WHITE,
        );
    }
}

impl eframe::App for App {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(
            storage,
            PREFS_KEY,
            &Prefs {
                tab: self.tab,
                armor: self.files.armor,
                decrypt_source: self.files.source,
                show_qr: self.identities.show_qr,
                theme: self.theme,
            },
        );
    }

    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            self.theme.apply(ctx);
            self.theme_applied = true;
        }
        self.handle_drops(ctx);
        self.handle_shortcuts(ctx);

        // Drain worker updates before drawing, so this frame shows the newest
        // progress rather than last frame's. A finished job's results are
        // folded into the queue rows and the job dropped, so the rows carry
        // their own answers and a later run knows which are already settled.
        let mut changed = false;
        for which in [FileAction::Seal, FileAction::Open] {
            let slot = match which {
                FileAction::Seal => &mut self.files.seal_job,
                FileAction::Open => &mut self.files.open_job,
            };
            if let Some(job) = slot.as_mut() {
                changed |= job.drain();
            }
            if slot.as_ref().is_some_and(|j| j.finished) {
                if let Some(job) = match which {
                    FileAction::Seal => self.files.seal_job.take(),
                    FileAction::Open => self.files.open_job.take(),
                } {
                    let summary = self.files.absorb(job);
                    self.status = Some(summary);
                    changed = true;
                }
            }
        }
        if changed {
            ctx.request_repaint();
        }

        self.drop_hint(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // 112, not 180. The rail carries an icon over a centred label now, so it
        // needs less width, and the content pane is the thing that wanted the
        // room. Matches PGPony Desktop's RAIL_WIDTH so the two apps sit at the
        // same proportions.
        egui::Panel::left("sidebar")
            .exact_size(crate::theme::RAIL_WIDTH)
            .resizable(false)
            .show(ui, |ui| {
                crate::theme::rail_head(ui);
                for (i, tab) in Tab::ALL.into_iter().enumerate() {
                    let response =
                        crate::theme::rail_item(ui, tab.icon(), tab.label(), self.tab == tab)
                            .on_hover_text(format!("{}{}", command_symbol(), i + 1));
                    if response.clicked() {
                        self.tab = tab;
                    }
                }
                // The identity card. Everything here has to wrap rather than
                // measure to its natural width: the rail is 112px and an
                // identity called "Laptop classic" is wider than that at any
                // readable size. The badges are the bare ◆ for the same reason
                // -- "◆ quantum-safe" as a capsule does not fit, and a clipped
                // capsule reads as a rendering fault rather than as a label.
                ui.add_space(crate::theme::space::LG);
                ui.separator();
                ui.add_space(crate::theme::space::SM);
                crate::theme::section(ui, "Identity");
                match self.store.active() {
                    Some(entry) => {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&entry.label)
                                    .font(egui::FontId::proportional(12.5))
                                    .color(crate::theme::ink(ui)),
                            )
                            .wrap(),
                        );
                        ui.horizontal(|ui| {
                            if entry.kind.is_post_quantum() {
                                ui.colored_label(crate::theme::PQ_BADGE, "◆")
                                    .on_hover_text("Quantum-safe");
                            }
                            if entry.encrypted {
                                ui.weak("passphrase");
                            }
                        });
                    }
                    None => {
                        ui.weak("none yet");
                    }
                }

                // Pinned to the foot of the sidebar. The bottom margin is not
                // decoration: without it the row sits flush against the window
                // edge and reads as clipped.
                // One cycling button, not a three-way segmented control.
                // `segmented` divides the available width evenly, and three
                // segments of a 96px interior leaves 32px each, which clips
                // "Light" and "Dark". This is temporary: appearance belongs on
                // the Settings destination, where there is room for the real
                // control, and it moves there when that screen lands.
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(crate::theme::space::MD);
                    let next = self.theme.next();
                    if crate::theme::secondary_button(ui, self.theme.label())
                        .on_hover_text(format!("Appearance. Click for {}.", next.label()))
                        .clicked()
                    {
                        self.theme = next;
                        next.apply(ui.ctx());
                    }
                    ui.add_space(crate::theme::space::TIGHT);
                    crate::theme::section(ui, "Appearance");
                    ui.add_space(crate::theme::space::SM);
                    ui.separator();
                });
            });

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.add_space(6.0);
            // The strip prefers live information over stale: what is running
            // now, else the last status line, else a quiet "Ready". Escape
            // clears the status; there is no button for it, because a footer
            // full of controls stops reading as a footer.
            let message = self
                .files
                .running_caption()
                .or_else(|| self.status.clone())
                .unwrap_or_else(|| "Ready".to_owned());
            let detail = self.store.active().map_or_else(String::new, |e| {
                if e.kind.is_post_quantum() {
                    format!("{} · quantum-safe", e.label)
                } else {
                    e.label.clone()
                }
            });
            crate::theme::status_bar(ui, &message, &detail, false);
            ui.add_space(6.0);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.tab {
                Tab::Files => panels::files::show(self, ui),
                Tab::Identities => panels::identities::show(self, ui),
                Tab::Recipients => panels::recipients::show(self, ui),
            });
        });
    }
}

/// A short human label for an identity kind, used in more than one panel.
#[must_use]
pub fn kind_label(kind: Kind) -> &'static str {
    kind.label()
}

/// How to write the command modifier for this platform, for hover hints.
#[must_use]
pub fn command_symbol() -> &'static str {
    if cfg!(target_os = "macos") {
        "⌘"
    } else {
        "Ctrl+"
    }
}

/// The per-OS config directory for AgePony.
#[must_use]
pub fn config_dir() -> PathBuf {
    directories::ProjectDirs::from("se", "norsehor", "AgePony").map_or_else(
        || PathBuf::from(".agepony"),
        |d| d.config_dir().to_path_buf(),
    )
}
