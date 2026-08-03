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

/// Which panel the sidebar has selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Tab {
    /// The encrypt panel.
    #[default]
    Encrypt,
    /// The decrypt panel.
    Decrypt,
    /// Identity management.
    Identities,
    /// The recipient book.
    Recipients,
}

impl Tab {
    pub(crate) const ALL: [Tab; 4] = [Tab::Encrypt, Tab::Decrypt, Tab::Identities, Tab::Recipients];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Tab::Encrypt => "Encrypt",
            Tab::Decrypt => "Decrypt",
            Tab::Identities => "Identities",
            Tab::Recipients => "Recipients",
        }
    }

    /// The rail glyph for this destination.
    ///
    /// Sealing and opening are the same padlock, shut and open. A label alone
    /// made the rail read as a list of words rather than as somewhere to go.
    pub(crate) const fn icon(self) -> char {
        match self {
            Tab::Encrypt => crate::theme::icon::LOCK,
            Tab::Decrypt => crate::theme::icon::LOCK_OPEN,
            Tab::Identities => crate::theme::icon::KEY_ROUND,
            Tab::Recipients => crate::theme::icon::USERS,
        }
    }
}

/// Everything the encrypt panel remembers between frames.
#[derive(Default)]
pub struct EncryptState {
    /// Files queued for encryption.
    pub inputs: Vec<PathBuf>,
    /// Names of the book entries that are ticked.
    pub picked: BTreeSet<String>,
    /// Recipients typed directly, one per line.
    pub extra: String,
    /// Use a passphrase instead of recipients.
    pub use_passphrase: bool,
    /// The passphrase, held only while the panel is open.
    pub passphrase: String,
    /// ASCII armor the output.
    pub armor: bool,
    /// The job in flight, if any.
    pub job: Option<Running>,
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

/// Everything the decrypt panel remembers between frames.
#[derive(Default)]
pub struct DecryptState {
    /// Files queued for decryption.
    pub inputs: Vec<PathBuf>,
    /// Where the identity comes from.
    pub source: DecryptSource,
    /// Identity files chosen when `source` is [`DecryptSource::File`].
    pub identity_files: Vec<PathBuf>,
    /// The file's passphrase, for [`DecryptSource::Passphrase`].
    pub passphrase: String,
    /// The passphrase that unlocks a protected identity file.
    pub identity_passphrase: String,
    /// The job in flight, if any.
    pub job: Option<Running>,
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
    pub(crate) const ALL: [ThemeChoice; 3] =
        [ThemeChoice::System, ThemeChoice::Light, ThemeChoice::Dark];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            ThemeChoice::System => "Auto",
            ThemeChoice::Light => "Light",
            ThemeChoice::Dark => "Dark",
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
    /// Selected sidebar tab.
    pub tab: Tab,
    /// Encrypt panel state.
    pub encrypt: EncryptState,
    /// Decrypt panel state.
    pub decrypt: DecryptState,
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
            encrypt: EncryptState {
                armor: prefs.armor,
                ..EncryptState::default()
            },
            decrypt: DecryptState {
                source: prefs.decrypt_source,
                ..DecryptState::default()
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
    /// Dropping while Encrypt or Decrypt is open honours that choice — the user
    /// said where they wanted it by being there. From the other tabs there is
    /// no such signal, so route on the extension and switch, which is almost
    /// always what was meant.
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

        let target = match self.tab {
            Tab::Encrypt => Tab::Encrypt,
            Tab::Decrypt => Tab::Decrypt,
            _ => {
                let looks_encrypted = dropped
                    .iter()
                    .all(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("age")));
                let t = if looks_encrypted {
                    Tab::Decrypt
                } else {
                    Tab::Encrypt
                };
                self.tab = t;
                t
            }
        };

        let count = dropped.len();
        if target == Tab::Decrypt {
            self.decrypt.inputs.extend(dropped);
            self.decrypt.inputs.dedup();
        } else {
            self.encrypt.inputs.extend(dropped);
            self.encrypt.inputs.dedup();
        }
        self.status = Some(format!(
            "Added {count} file{} to {}",
            if count == 1 { "" } else { "s" },
            target.label()
        ));
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
                2 => Key::Num3,
                _ => Key::Num4,
            };
            if ctx.input_mut(|inp| inp.consume_key(Modifiers::COMMAND, key)) {
                self.tab = *tab;
            }
        }

        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::O)) {
            self.choose_files();
        }

        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::Enter)) {
            match self.tab {
                Tab::Encrypt => crate::panels::encrypt::start(self, ctx.clone()),
                Tab::Decrypt => crate::panels::decrypt::start(self, ctx.clone()),
                _ => {}
            }
        }

        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) {
            self.escape();
        }
    }

    fn choose_files(&mut self) {
        match self.tab {
            Tab::Encrypt => {
                if let Some(files) = rfd::FileDialog::new().pick_files() {
                    self.encrypt.inputs.extend(files);
                    self.encrypt.inputs.dedup();
                }
            }
            Tab::Decrypt => {
                if let Some(files) = rfd::FileDialog::new()
                    .add_filter("age files", &["age", "txt"])
                    .pick_files()
                {
                    self.decrypt.inputs.extend(files);
                    self.decrypt.inputs.dedup();
                }
            }
            _ => {}
        }
    }

    /// Escape: back out of whatever is open, innermost first.
    fn escape(&mut self) {
        if let Some(job) = self.encrypt.job.as_ref().filter(|j| j.in_flight()) {
            job.cancel();
            return;
        }
        if let Some(job) = self.decrypt.job.as_ref().filter(|j| j.in_flight()) {
            job.cancel();
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
            match self.tab {
                Tab::Decrypt => "Drop to decrypt",
                _ => "Drop to encrypt",
            },
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
                armor: self.encrypt.armor,
                decrypt_source: self.decrypt.source,
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
        // progress rather than last frame's.
        let mut changed = false;
        if let Some(job) = self.encrypt.job.as_mut() {
            changed |= job.drain();
        }
        if let Some(job) = self.decrypt.job.as_mut() {
            changed |= job.drain();
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
            .exact_size(112.0)
            .resizable(false)
            .show(ui, |ui| {
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    ui.add_space(2.0);
                    let (mark_rect, _) =
                        ui.allocate_exact_size(egui::Vec2::splat(26.0), egui::Sense::hover());
                    crate::theme::draw_mark(
                        ui,
                        mark_rect,
                        crate::theme::TEAL_CORE,
                        ui.visuals().panel_fill,
                    );
                    ui.label(
                        egui::RichText::new("AgePony")
                            .font(crate::theme::semibold(20.0))
                            .color(crate::theme::ink(ui)),
                    );
                });
                ui.add_space(10.0);
                let rule = egui::Rect::from_min_size(
                    ui.cursor().min,
                    egui::vec2(ui.available_width(), 2.0),
                );
                crate::theme::gradient_rule(ui, rule);
                ui.add_space(12.0);
                for (i, tab) in Tab::ALL.into_iter().enumerate() {
                    let response = crate::theme::rail_item(
                        ui,
                        tab.icon(),
                        tab.label(),
                        self.tab == tab,
                    )
                    .on_hover_text(format!("{}{}", command_symbol(), i + 1));
                    if response.clicked() {
                        self.tab = tab;
                    }
                }
                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);
                ui.label("Active identity");
                match self.store.active() {
                    Some(entry) => {
                        ui.strong(&entry.label);
                        if entry.kind.is_post_quantum() {
                            ui.colored_label(crate::theme::PQ_BADGE, "◆ quantum-safe");
                        }
                        if entry.encrypted {
                            crate::theme::passphrase_badge(ui);
                        }
                    }
                    None => {
                        ui.weak("none yet");
                    }
                }

                // Pinned to the foot of the sidebar. The bottom margin is not
                // decoration: without it the row sits flush against the window
                // edge and reads as clipped.
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(14.0);
                    let selected = ThemeChoice::ALL
                        .iter()
                        .position(|c| *c == self.theme)
                        .unwrap_or(0);
                    let labels: Vec<&str> = ThemeChoice::ALL.iter().map(|c| c.label()).collect();
                    if let Some(i) = crate::theme::segmented(ui, &labels, selected) {
                        if let Some(choice) = ThemeChoice::ALL.get(i) {
                            self.theme = *choice;
                            choice.apply(ui.ctx());
                        }
                    }
                    ui.add_space(4.0);
                    crate::theme::section(ui, "Appearance");
                    ui.add_space(8.0);
                    ui.separator();
                });
            });

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                let message = self.status.clone().unwrap_or_default();
                ui.label(message);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.status.is_some() && ui.small_button("clear").clicked() {
                        self.status = None;
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.tab {
                Tab::Encrypt => panels::encrypt::show(self, ui),
                Tab::Decrypt => panels::decrypt::show(self, ui),
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
