//! Detail ▸ Attachments (specs/05-ui.md §2.3, specs/03-sync.md §1.1): add, preview, save a
//! decrypted copy, remove.
//!
//! Sealing a new file needs `&mut SyncedVault`, so adds go through `run_bg` like every
//! other vault-moving task: the vault is inside the task meanwhile and the detail column
//! renders a snapshot of the item (`held`). Reading a blob that is on disk does not move
//! the vault: `open_attachment` runs on the main thread and the returned reader (it owns
//! its file and key) decrypts on the background executor. An evicted blob may take up to
//! 30 s to download, so that read moves the vault through `run_bg` instead.
//!
//! Results that arrive after a lock or vault switch are dropped without a toast. A lock
//! during an add removes the new references again before the vault locks, so an add the
//! user never saw finish never reaches the file. A lock during "Save decrypted copy"
//! cancels the write and deletes the temporary file.
//!
//! The preview holds at most one decrypted attachment, wiped when the selection changes
//! or the vault locks. Names and contents never reach a log.
//!
//! # Interpretations
//!
//! - Preview is offered by file extension: png/jpg/jpeg/gif up to 20 MB, and text
//!   extensions (or none) under 1 MB whose content is UTF-8 without NUL bytes. HEIC is
//!   left out: gpui's decoder (the `image` crate) cannot read it.
//! - Image bytes handed to gpui (`Image`, `RenderImage`) are freed when the preview goes,
//!   not zeroized: gpui owns those buffers. The decrypted text buffer we own is zeroized,
//!   but the lines on screen are copied into gpui strings (and its text layout cache) for
//!   rendering, like a revealed password; those copies are freed, not zeroized.
//! - Images larger than 50 megapixels in total (GIF: canvas times frames) are not decoded;
//!   the size is read from the file header first.

use std::io::{self, Read, Write as _};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gpui::{Context, RenderImage, SharedString, SvgRenderer};
use vault_core::attachment::MAX_ATTACHMENT_SIZE;
use vault_core::{AttachmentError, Item, Millis, Uuid};
use vault_sync::{AttachmentState, SyncError, SyncedVault};
use zeroize::Zeroizing;

use super::{AppState, Busy, Mode, Outcome, Toast};
use crate::text;

/// Text previews are offered below this size ("UTF-8 text under 1 MB").
pub const TEXT_PREVIEW_MAX: u64 = 1_000_000;
/// Image previews are offered up to this size; larger images would decode to hundreds of
/// megabytes of pixels.
pub const IMAGE_PREVIEW_MAX: u64 = 20_000_000;
/// Longest line the text preview shows; the rest is cut (the copy on disk is complete).
const PREVIEW_LINE_MAX: usize = 2_000;
/// Copy buffer for "Save decrypted copy" (wiped after use).
const COPY_CHUNK: usize = 64 * 1024;

pub const TOO_LARGE: &str = "File is larger than 100 MB";
const MISSING: &str = "This attachment is missing. It has not synced to this Mac yet, or the vault was restored from a backup.";

const IMAGE_EXTS: [(&str, gpui::ImageFormat); 4] = [
    ("png", gpui::ImageFormat::Png),
    ("jpg", gpui::ImageFormat::Jpeg),
    ("jpeg", gpui::ImageFormat::Jpeg),
    ("gif", gpui::ImageFormat::Gif),
];
const TEXT_EXTS: [&str; 24] = [
    "txt", "text", "md", "markdown", "csv", "tsv", "json", "xml", "yaml", "yml", "toml", "ini",
    "cfg", "conf", "log", "pem", "crt", "cer", "key", "pub", "asc", "env", "html", "htm",
];

/// The four `SyncedVault` attachment calls, behind a trait so tests can fake them.
pub trait AttachmentStore: Send + Sync {
    fn add(
        &self,
        vault: &mut SyncedVault,
        item: Uuid,
        name: &str,
        data: &mut dyn Read,
        size: u64,
        now: Millis,
    ) -> Result<Uuid, SyncError>;
    fn open(
        &self,
        vault: &SyncedVault,
        item: Uuid,
        id: Uuid,
    ) -> Result<Box<dyn Read + Send>, SyncError>;
    fn state(&self, vault: &SyncedVault, id: Uuid) -> AttachmentState;
    fn remove(
        &self,
        vault: &mut SyncedVault,
        item: Uuid,
        id: Uuid,
        now: Millis,
    ) -> Result<(), SyncError>;
}

/// The real store: `vault-sync`'s blobs next to the vault file.
#[cfg_attr(test, allow(dead_code))]
pub struct SyncStore;

impl AttachmentStore for SyncStore {
    fn add(
        &self,
        vault: &mut SyncedVault,
        item: Uuid,
        name: &str,
        data: &mut dyn Read,
        size: u64,
        now: Millis,
    ) -> Result<Uuid, SyncError> {
        vault.add_attachment(item, name, data, size, now)
    }

    fn open(
        &self,
        vault: &SyncedVault,
        item: Uuid,
        id: Uuid,
    ) -> Result<Box<dyn Read + Send>, SyncError> {
        Ok(Box::new(vault.open_attachment(item, id)?))
    }

    fn state(&self, vault: &SyncedVault, id: Uuid) -> AttachmentState {
        vault.attachment_state(id)
    }

    fn remove(
        &self,
        vault: &mut SyncedVault,
        item: Uuid,
        id: Uuid,
        now: Millis,
    ) -> Result<(), SyncError> {
        vault.remove_attachment(item, id, now)
    }
}

#[cfg_attr(test, allow(dead_code))]
pub fn sync_store() -> Arc<dyn AttachmentStore> {
    Arc::new(SyncStore)
}

/// What Preview can show for a file, decided by its name and size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewKind {
    Image(gpui::ImageFormat),
    Text,
}

/// The preview kind for `name` / `size`, or `None` (no Preview button).
pub fn preview_kind(name: &str, size: u64) -> Option<PreviewKind> {
    let ext = Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    match ext.as_deref() {
        Some(ext) => {
            if let Some((_, format)) = IMAGE_EXTS.iter().find(|(e, _)| *e == ext) {
                return (size <= IMAGE_PREVIEW_MAX).then_some(PreviewKind::Image(*format));
            }
            (TEXT_EXTS.contains(&ext) && size < TEXT_PREVIEW_MAX).then_some(PreviewKind::Text)
        }
        None => (size < TEXT_PREVIEW_MAX).then_some(PreviewKind::Text),
    }
}

/// User-facing label for a blob state; `None` when the file is here.
pub fn state_label(state: AttachmentState) -> Option<&'static str> {
    match state {
        AttachmentState::Present => None,
        AttachmentState::NotDownloaded => Some("Not downloaded yet"),
        AttachmentState::Missing => Some("Missing"),
    }
}

/// A file being sealed: shown as a row with a spinner.
#[derive(Debug, Clone)]
pub struct PendingFile {
    pub item: Uuid,
    pub name: SharedString,
    pub size: u64,
}

/// "Save decrypted copy…" waiting for the confirm sheet.
#[derive(Debug, Clone)]
pub struct SaveRequest {
    pub item: Uuid,
    pub id: Uuid,
    pub name: String,
    pub path: PathBuf,
    lock_gen: u64,
    epoch: u64,
}

/// Decrypted UTF-8 text and its line ranges. The buffer is wiped on drop.
pub struct TextPreview {
    text: Zeroizing<String>,
    lines: Vec<Range<usize>>,
}

impl TextPreview {
    fn new(text: Zeroizing<String>) -> Self {
        let mut lines = Vec::new();
        let mut start = 0;
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                lines.push(start..i);
                start = i + 1;
            }
        }
        if start < text.len() || lines.is_empty() {
            lines.push(start..text.len());
        }
        Self { text, lines }
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Line `ix` without its `\r`, cut at `PREVIEW_LINE_MAX` bytes on a char boundary.
    pub fn line(&self, ix: usize) -> &str {
        let Some(r) = self.lines.get(ix) else {
            return "";
        };
        let line = self.text[r.clone()].trim_end_matches('\r');
        if line.len() <= PREVIEW_LINE_MAX {
            return line;
        }
        let mut end = PREVIEW_LINE_MAX;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        &line[..end]
    }
}

/// What the preview area shows.
#[derive(Clone)]
pub enum PreviewContent {
    Image(Arc<RenderImage>),
    Text(Rc<TextPreview>),
    /// Why there is nothing to show ("Not UTF-8 text").
    Unavailable(SharedString),
}

/// The single decrypted attachment in memory.
pub struct Preview {
    pub item: Uuid,
    pub id: Uuid,
    pub content: PreviewContent,
}

/// Attachment UI state on `AppState`.
#[derive(Default)]
pub struct AttachmentsUi {
    /// Files being sealed (one batch at a time).
    pub pending: Vec<PendingFile>,
    /// Inline "Remove '<name>'?" confirm for this attachment.
    pub remove_confirm: Option<Uuid>,
    /// The confirm sheet before writing plaintext to disk.
    pub save_confirm: Option<SaveRequest>,
    /// Attachment whose Preview or Save is decrypting.
    pub reading: Option<Uuid>,
    pub preview: Option<Preview>,
    /// The selected item and its blob states while the vault is inside an attachment task.
    held: Option<(Item, Vec<(Uuid, AttachmentState)>)>,
    /// Bumped by `clear`; a read started under an older ticket is dropped.
    ticket: u64,
    /// Set by `clear`: an in-flight "Save decrypted copy" stops and deletes its temp file.
    cancel: Arc<AtomicBool>,
    /// Dropped preview images still in the sprite atlas.
    evict: Vec<Arc<RenderImage>>,
}

impl AttachmentsUi {
    /// Frees a preview: a text buffer is zeroized on drop; an image is queued to leave
    /// every window's sprite atlas.
    fn retire(&mut self, preview: Option<Preview>) {
        if let Some(Preview {
            content: PreviewContent::Image(image),
            ..
        }) = preview
        {
            self.evict.push(image);
        }
    }
}

/// Where a decrypted stream goes.
enum ReadPurpose {
    Preview(PreviewKind),
    Save(PathBuf),
}

/// Background result of a read, built off the main thread (hence `Send`).
enum ReadResult {
    Image(Arc<RenderImage>),
    Text(TextPreview),
    Unavailable(&'static str),
    Saved(PathBuf),
    Failed(String),
    Cancelled,
}

/// The read a result belongs to.
#[derive(Debug, Clone, Copy)]
struct ReadTarget {
    item: Uuid,
    id: Uuid,
    ticket: u64,
    lock_gen: u64,
    epoch: u64,
}

impl AppState {
    /// The selected item for the detail column, including while an attachment task holds
    /// the vault (then a snapshot taken when it started).
    pub fn shown_item(&self) -> Option<&Item> {
        self.selected_item().or_else(|| {
            let (item, _) = self.attachments.held.as_ref()?;
            (Some(item.id) == self.selection && !self.locked).then_some(item)
        })
    }

    /// Whether `id`'s blob is here, evicted or missing. Cheap (a `stat`), no download.
    pub fn attachment_state(&self, id: Uuid) -> AttachmentState {
        if let Some(vault) = self.vault.as_ref() {
            return self.attach_store.state(vault, id);
        }
        self.attachments
            .held
            .as_ref()
            .and_then(|(_, states)| states.iter().find(|(a, _)| *a == id))
            .map_or(AttachmentState::Present, |(_, s)| *s)
    }

    /// Whether files can be added to the selected item now (read or edit mode, not a new
    /// item that is not in the vault yet).
    pub fn can_attach(&self) -> bool {
        self.main_active() && !matches!(self.mode, Mode::New(..)) && self.selected_item().is_some()
    }

    /// "Add file…": the open panel (several files), then [`Self::add_attachment_files`].
    pub fn pick_attachment_files(&mut self, cx: &mut Context<Self>) {
        if !self.can_attach() {
            return;
        }
        let Some(item) = self.selection else {
            return;
        };
        let (lock_gen, epoch) = (self.lock_gen, self.epoch);
        let rx = cx.prompt_for_paths(gpui::PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some("Add".into()),
        });
        cx.spawn(async move |this, cx| {
            let paths = match rx.await {
                Ok(Ok(Some(paths))) => paths,
                _ => return,
            };
            this.update(cx, |this, cx| {
                // The panel is modal-less: the user may have locked or moved on meanwhile.
                if this.lock_gen == lock_gen && this.epoch == epoch && this.selection == Some(item)
                {
                    this.add_attachment_files(paths, cx);
                }
            })
            .ok();
        })
        .detach();
    }

    /// Seals `paths` into the selected item (drop or open panel). Folders and files over
    /// 100 MB are skipped with a toast.
    pub fn add_attachment_files(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        if !self.can_attach() {
            return;
        }
        if self.busy.is_some() {
            self.show_toast("Wait for the current task to finish", cx);
            return;
        }
        let Some(item) = self.selection else {
            return;
        };
        let (mut too_large, mut not_files) = (0usize, 0usize);
        let mut files = Vec::new();
        for path in paths {
            match std::fs::metadata(&path) {
                Ok(m) if m.is_file() && m.len() > MAX_ATTACHMENT_SIZE => too_large += 1,
                Ok(m) if m.is_file() => files.push((path.clone(), text::file_name(&path), m.len())),
                _ => not_files += 1,
            }
        }
        if let Some(message) = skipped_message(too_large, not_files) {
            self.show_toast(message, cx);
        }
        if files.is_empty() {
            return;
        }
        self.attachments.pending = files
            .iter()
            .map(|(_, name, size)| PendingFile {
                item,
                name: name.clone().into(),
                size: *size,
            })
            .collect();
        self.hold_selected();
        let Some(mut vault) = self.vault.take() else {
            self.attachments.pending.clear();
            self.attachments.held = None;
            return;
        };
        let store = self.attach_store.clone();
        let now = text::now_millis();
        self.run_bg_cx(
            Busy::Attaching,
            cx,
            move || {
                let mut added = Vec::new();
                let mut failed = Vec::new();
                for (path, name, size) in files {
                    let mut file = match std::fs::File::open(&path) {
                        Ok(f) => f,
                        Err(e) => {
                            failed.push((name, e.to_string()));
                            continue;
                        }
                    };
                    match store.add(&mut vault, item, &name, &mut file, size, now) {
                        Ok(id) => added.push(id),
                        Err(e) => failed.push((name, add_error(&e))),
                    }
                }
                (vault, store, added, failed)
            },
            move |this, (mut vault, store, added, failed), outcome, cx| {
                this.attachments.pending.clear();
                this.attachments.held = None;
                if outcome != Outcome::Fresh {
                    // Locked or switched before the user saw the result: take the new
                    // references out again (the blobs go with orphan cleanup).
                    let stuck = added
                        .into_iter()
                        .filter(|id| store.remove(&mut vault, item, *id, now).is_err())
                        .count();
                    this.return_vault(vault, outcome, cx);
                    if stuck > 0 && outcome == Outcome::Locked {
                        this.toast = Some(Toast::window(
                            "A file added just before locking could not be taken out again. \
                             Check the item's attachments after unlocking.",
                        ));
                    }
                    return;
                }
                let saved = (!added.is_empty()).then(|| vault.save());
                this.vault = Some(vault);
                this.vault_changed();
                let save_error = saved.and_then(|r| this.record_save(r));
                this.resume_autosave(cx);
                let message = match (failed.as_slice(), save_error) {
                    ([], None) => None,
                    ([(name, why)], None) => {
                        Some(format!("Could not add \u{2018}{name}\u{2019}: {why}"))
                    }
                    ([], Some(e)) => Some(format!("Added, but not saved yet: {e}")),
                    (many, _) => Some(format!("{} files could not be added", many.len())),
                };
                if let Some(message) = message {
                    this.toast = Some(Toast::window(message));
                }
            },
        );
    }

    /// Snapshot of the selected item and its blob states, shown while the vault is away.
    fn hold_selected(&mut self) {
        self.attachments.held = self.selected_item().cloned().map(|item| {
            let states = item
                .attachments
                .iter()
                .map(|a| (a.id, self.attachment_state(a.id)))
                .collect();
            (item, states)
        });
    }

    /// Puts the vault back after an attachment task. After a lock or vault switch it does
    /// what `lock` could not while the vault was in the task: save pending edits (a Remove
    /// whose autosave had not run, say), then lock. Fresh: resume a lost autosave.
    fn return_vault(&mut self, mut vault: SyncedVault, outcome: Outcome, cx: &mut Context<Self>) {
        if outcome == Outcome::Fresh {
            self.vault = Some(vault);
            self.resume_autosave(cx);
            return;
        }
        let saved = vault.is_dirty().then(|| vault.save());
        // Dropping after a vault switch zeroizes the keys.
        vault.lock();
        if outcome == Outcome::Locked {
            self.vault = Some(vault);
            if let Some(e) = saved.and_then(|r| self.record_save(r)) {
                self.toast = Some(Toast::window(format!("Could not save before locking: {e}")));
            }
        }
    }

    /// An autosave that fired while the vault was in a task found nothing to save and
    /// cleared its timer: start a new one if edits are still unsaved.
    fn resume_autosave(&mut self, cx: &mut Context<Self>) {
        if !self.locked && self.vault.as_ref().is_some_and(SyncedVault::is_dirty) {
            self.schedule_autosave(cx);
        }
    }

    /// Remove is an edit-mode action (owner decision): read mode only previews and saves.
    fn can_remove_attachments(&self) -> bool {
        self.main_active() && self.busy.is_none() && matches!(self.mode, Mode::Edit(_))
    }

    /// The row's Remove button (edit mode): show the inline confirm.
    pub fn request_remove_attachment(&mut self, id: Uuid, cx: &mut Context<Self>) {
        if self.can_remove_attachments() {
            self.attachments.remove_confirm = Some(id);
            cx.notify();
        }
    }

    pub fn cancel_remove_attachment(&mut self, cx: &mut Context<Self>) {
        if self.attachments.remove_confirm.take().is_some() {
            cx.notify();
        }
    }

    /// The inline confirm's "Remove": drops the reference (the blob goes with orphan
    /// cleanup) and autosaves.
    pub fn confirm_remove_attachment(&mut self, id: Uuid, cx: &mut Context<Self>) {
        self.attachments.remove_confirm = None;
        if !self.can_remove_attachments() {
            cx.notify();
            return;
        }
        let Some(item) = self.selected_item().map(|i| i.id) else {
            return;
        };
        if self
            .attachments
            .preview
            .as_ref()
            .is_some_and(|p| p.id == id)
        {
            self.close_preview(cx);
        }
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        match self
            .attach_store
            .remove(vault, item, id, text::now_millis())
        {
            Ok(()) => {
                self.vault_changed();
                self.schedule_autosave(cx);
            }
            Err(e) => self.show_toast(format!("Could not remove the attachment: {e}"), cx),
        }
        cx.notify();
    }

    /// Preview: shows the attachment under its row, or hides it if it is showing.
    pub fn toggle_attachment_preview(&mut self, id: Uuid, cx: &mut Context<Self>) {
        if self
            .attachments
            .preview
            .as_ref()
            .is_some_and(|p| p.id == id)
        {
            self.close_preview(cx);
            return;
        }
        let Some(kind) = self
            .shown_attachment(id)
            .and_then(|(name, size)| preview_kind(&name, size))
        else {
            return;
        };
        self.start_read(id, ReadPurpose::Preview(kind), cx);
    }

    pub fn close_preview(&mut self, cx: &mut Context<Self>) {
        if let Some(p) = self.attachments.preview.take() {
            self.attachments.retire(Some(p));
            self.evict_images(cx);
            cx.notify();
        }
    }

    /// "Save decrypted copy…": the save panel, then the confirm sheet.
    pub fn save_attachment_copy(&mut self, id: Uuid, cx: &mut Context<Self>) {
        if !self.main_active() || self.busy.is_some() || self.attachments.reading.is_some() {
            return;
        }
        let (Some(item), Some((name, _))) = (self.selection, self.shown_attachment(id)) else {
            return;
        };
        let dir = dirs::download_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("/"));
        let (lock_gen, epoch) = (self.lock_gen, self.epoch);
        let pick = crate::ui::pick_new_path(&dir, &name, cx);
        cx.spawn(async move |this, cx| {
            let Some(path) = pick.await else {
                return;
            };
            this.update(cx, |this, cx| {
                let request = SaveRequest {
                    item,
                    id,
                    name,
                    path,
                    lock_gen,
                    epoch,
                };
                this.save_path_chosen(request, cx);
            })
            .ok();
        })
        .detach();
    }

    /// The save panel returned `request.path`: ask before writing plaintext.
    fn save_path_chosen(&mut self, request: SaveRequest, cx: &mut Context<Self>) {
        if self.lock_gen != request.lock_gen
            || self.epoch != request.epoch
            || self.selection != Some(request.item)
            || self.locked
        {
            return;
        }
        self.attachments.save_confirm = Some(request);
        cx.notify();
    }

    /// What the save panel's result does, minus the panel (tests).
    #[cfg(test)]
    pub fn save_attachment_to(&mut self, id: Uuid, path: PathBuf, cx: &mut Context<Self>) {
        let (Some(item), Some((name, _))) = (self.selection, self.shown_attachment(id)) else {
            return;
        };
        let request = SaveRequest {
            item,
            id,
            name,
            path,
            lock_gen: self.lock_gen,
            epoch: self.epoch,
        };
        self.save_path_chosen(request, cx);
    }

    pub fn cancel_save_copy(&mut self, cx: &mut Context<Self>) {
        if self.attachments.save_confirm.take().is_some() {
            cx.notify();
        }
    }

    /// The confirm sheet's "Save Copy": decrypt and write with mode 0600.
    pub fn confirm_save_copy(&mut self, cx: &mut Context<Self>) {
        let Some(request) = self.attachments.save_confirm.take() else {
            return;
        };
        if self.lock_gen != request.lock_gen
            || self.epoch != request.epoch
            || self.selection != Some(request.item)
        {
            cx.notify();
            return;
        }
        self.start_read(request.id, ReadPurpose::Save(request.path), cx);
    }

    /// Name and size of attachment `id` on the shown item.
    fn shown_attachment(&self, id: Uuid) -> Option<(String, u64)> {
        let a = self.shown_item()?.attachments.iter().find(|a| a.id == id)?;
        Some((a.name.clone(), a.size))
    }

    /// Decrypts attachment `id` of the selected item for `purpose`, off the main thread.
    fn start_read(&mut self, id: Uuid, purpose: ReadPurpose, cx: &mut Context<Self>) {
        if !self.main_active() || self.attachments.reading.is_some() {
            return;
        }
        let Some((item, size)) = self
            .selected_item()
            .and_then(|i| Some((i.id, i.attachments.iter().find(|a| a.id == id)?.size)))
        else {
            return;
        };
        let target = ReadTarget {
            item,
            id,
            ticket: self.attachments.ticket,
            lock_gen: self.lock_gen,
            epoch: self.epoch,
        };
        let svg = cx.svg_renderer();
        let cancel = self.attachments.cancel.clone();
        match self.attachment_state(id) {
            AttachmentState::Missing => {
                self.show_toast(MISSING, cx);
            }
            AttachmentState::Present => {
                let Some(vault) = self.vault.as_ref() else {
                    return;
                };
                let reader = match self.attach_store.open(vault, item, id) {
                    Ok(reader) => reader,
                    Err(e) => {
                        self.show_toast(read_error(&e), cx);
                        return;
                    }
                };
                self.attachments.reading = Some(id);
                cx.notify();
                let task = cx
                    .background_executor()
                    .spawn(async move { consume(reader, size, purpose, svg, &cancel) });
                cx.spawn(async move |this, cx| {
                    let result = task.await;
                    this.update(cx, |this, cx| {
                        this.read_finished(target, result, cx);
                        cx.notify();
                    })
                    .ok();
                })
                .detach();
            }
            AttachmentState::NotDownloaded => {
                if self.busy.is_some() {
                    self.show_toast("Wait for the current task to finish", cx);
                    return;
                }
                // `open_attachment` waits for the download: move the vault off the main thread.
                self.hold_selected();
                let Some(vault) = self.vault.take() else {
                    return;
                };
                self.attachments.reading = Some(id);
                let store = self.attach_store.clone();
                self.run_bg_cx(
                    Busy::ReadingAttachment,
                    cx,
                    move || {
                        let result = match store.open(&vault, item, id) {
                            Ok(reader) => consume(reader, size, purpose, svg, &cancel),
                            Err(e) => ReadResult::Failed(read_error(&e)),
                        };
                        (vault, result)
                    },
                    move |this, (vault, result), outcome, cx| {
                        this.attachments.held = None;
                        this.return_vault(vault, outcome, cx);
                        this.read_finished(target, result, cx);
                    },
                );
            }
        }
    }

    fn read_finished(&mut self, target: ReadTarget, result: ReadResult, cx: &mut Context<Self>) {
        self.read_finished_quiet(target, result);
        self.evict_images(cx);
    }

    /// Installs a read result unless the session it belongs to is gone. Needs no `cx`
    /// (it also runs as a `run_bg` finish); toasts are set directly.
    fn read_finished_quiet(&mut self, target: ReadTarget, result: ReadResult) {
        if self.attachments.reading == Some(target.id) {
            self.attachments.reading = None;
        }
        let outlived = self.locked
            || self.lock_gen != target.lock_gen
            || self.epoch != target.epoch
            || self.attachments.ticket != target.ticket;
        if outlived {
            // Dropped unread; a decrypted buffer is wiped here.
            return;
        }
        let content = match result {
            ReadResult::Image(image) => PreviewContent::Image(image),
            ReadResult::Text(text) => PreviewContent::Text(Rc::new(text)),
            ReadResult::Unavailable(why) => PreviewContent::Unavailable(why.into()),
            ReadResult::Saved(path) => {
                self.toast = Some(Toast::window(format!(
                    "Saved a decrypted copy to {}",
                    text::file_name(&path)
                )));
                return;
            }
            ReadResult::Failed(message) => {
                self.toast = Some(Toast::window(message));
                return;
            }
            ReadResult::Cancelled => return,
        };
        if self.selection != Some(target.item) {
            return;
        }
        let old = self.attachments.preview.replace(Preview {
            item: target.item,
            id: target.id,
            content,
        });
        self.attachments.retire(old);
    }

    /// Takes dropped images out of the sprite atlas (needs the `cx` that `run_bg`'s
    /// finish lacks, hence the queue).
    fn evict_images(&mut self, cx: &mut Context<Self>) {
        for image in std::mem::take(&mut self.attachments.evict) {
            cx.defer(move |cx| cx.drop_image(image, None));
        }
    }

    /// Drops the preview and confirms that belong to another item. Called by the detail
    /// column on every render, so a selection change wipes the decrypted preview at once.
    pub fn follow_attachment_selection(&mut self, cx: &mut Context<Self>) {
        let selection = self.selection;
        if self
            .attachments
            .preview
            .as_ref()
            .is_some_and(|p| Some(p.item) != selection)
        {
            let old = self.attachments.preview.take();
            self.attachments.retire(old);
        }
        if self
            .attachments
            .save_confirm
            .as_ref()
            .is_some_and(|r| Some(r.item) != selection)
        {
            self.attachments.save_confirm = None;
        }
        self.evict_images(cx);
        if !matches!(self.mode, Mode::Edit(_)) {
            self.attachments.remove_confirm = None;
        }
        if let Some(id) = self.attachments.remove_confirm
            && !self
                .selected_item()
                .is_some_and(|i| i.attachments.iter().any(|a| a.id == id))
        {
            self.attachments.remove_confirm = None;
        }
    }

    /// Lock / vault switch: wipe the preview, cancel a running save, forget confirms.
    pub(super) fn clear_attachments(&mut self, cx: &mut Context<Self>) {
        let ui = &mut self.attachments;
        ui.cancel.store(true, Ordering::SeqCst);
        ui.cancel = Arc::new(AtomicBool::new(false));
        ui.ticket = ui.ticket.wrapping_add(1);
        ui.remove_confirm = None;
        ui.save_confirm = None;
        ui.reading = None;
        let old = ui.preview.take();
        ui.retire(old);
        self.evict_images(cx);
    }

    #[cfg(test)]
    pub fn set_attachment_store(&mut self, store: Arc<dyn AttachmentStore>) {
        self.attach_store = store;
    }
}

/// Toast text for a failed add. Never contains file contents.
fn add_error(e: &SyncError) -> String {
    match e {
        SyncError::Attachment(AttachmentError::TooLarge { .. }) => TOO_LARGE.into(),
        SyncError::Attachment(AttachmentError::SizeMismatch { .. }) => {
            "the file changed while it was being added".into()
        }
        other => other.to_string(),
    }
}

/// Toast text for a failed open or read.
fn read_error(e: &SyncError) -> String {
    match e {
        SyncError::AttachmentMissing(_) => MISSING.into(),
        SyncError::AttachmentNotDownloaded(_) => {
            "The attachment did not download in time. Try again later.".into()
        }
        SyncError::AttachmentTampered(_) => {
            "This attachment failed its integrity check and may have been tampered with.".into()
        }
        other => format!("Could not read the attachment: {other}"),
    }
}

/// Toast text for an `io::Error` from the decrypting reader.
fn stream_error(e: &io::Error) -> String {
    match e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<SyncError>())
    {
        Some(inner) => read_error(inner),
        None => format!("Could not read the attachment: {e}"),
    }
}

/// Runs on the background executor: reads the decrypted stream into a preview or a file.
fn consume(
    mut reader: Box<dyn Read + Send>,
    size: u64,
    purpose: ReadPurpose,
    svg: SvgRenderer,
    cancel: &AtomicBool,
) -> ReadResult {
    match purpose {
        ReadPurpose::Save(path) => match write_plain(&mut *reader, &path, cancel) {
            Ok(true) => ReadResult::Saved(path),
            Ok(false) => ReadResult::Cancelled,
            Err(e) => ReadResult::Failed(stream_error(&e)),
        },
        ReadPurpose::Preview(kind) => {
            let bytes = match read_all(&mut *reader, size, cancel) {
                Ok(Some(bytes)) => bytes,
                Ok(None) => return ReadResult::Cancelled,
                Err(e) => return ReadResult::Failed(stream_error(&e)),
            };
            match kind {
                PreviewKind::Text => decode_text(bytes),
                PreviewKind::Image(format) => {
                    if !image_fits(format, &bytes) {
                        return ReadResult::Unavailable("No preview: this image is too large.");
                    }
                    // gpui takes ownership of the encoded bytes; they are freed, not wiped.
                    let image = gpui::Image::from_bytes(format, bytes.to_vec());
                    match image.to_image_data(svg) {
                        Ok(render) => ReadResult::Image(render),
                        Err(_) => ReadResult::Unavailable("This image could not be displayed."),
                    }
                }
            }
        }
    }
}

/// Reads the whole decrypted stream into a zeroizing buffer, checking `cancel` (lock)
/// between chunks. `Ok(None)` = cancelled; the partial buffer is wiped.
fn read_all(
    reader: &mut dyn Read,
    size: u64,
    cancel: &AtomicBool,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(usize::try_from(size).unwrap_or(0)));
    let mut chunk = Zeroizing::new(vec![0u8; COPY_CHUNK]);
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(Some(bytes));
        }
        if bytes.len() + n > bytes.capacity() {
            // More than the reference said: never let the Vec reallocate (the old buffer
            // would be freed unwiped).
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "attachment is longer than its reference",
            ));
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
}

/// Most pixels (summed over GIF frames) a preview decodes.
pub const IMAGE_PREVIEW_MAX_PIXELS: u64 = 50_000_000;

/// True when the header says the decoded image stays within `IMAGE_PREVIEW_MAX_PIXELS`.
/// Unknown or malformed headers are refused (nothing is decoded).
fn image_fits(format: gpui::ImageFormat, bytes: &[u8]) -> bool {
    image_pixels(format, bytes).is_some_and(|px| px <= IMAGE_PREVIEW_MAX_PIXELS)
}

/// Decoded pixel count from the header: PNG IHDR, JPEG SOFn, GIF canvas × frames.
fn image_pixels(format: gpui::ImageFormat, b: &[u8]) -> Option<u64> {
    let be16 = |i: usize| Some(u64::from(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?])));
    let be32 = |i: usize| {
        Some(u64::from(u32::from_be_bytes(
            b.get(i..i + 4)?.try_into().ok()?,
        )))
    };
    match format {
        gpui::ImageFormat::Png => {
            (b.get(12..16)? == b"IHDR").then_some(())?;
            Some(be32(16)? * be32(20)?)
        }
        gpui::ImageFormat::Jpeg => {
            let mut i = 2;
            loop {
                if *b.get(i)? != 0xFF {
                    return None;
                }
                let marker = *b.get(i + 1)?;
                if marker == 0xFF {
                    i += 1;
                    continue;
                }
                let is_sof = matches!(marker, 0xC0..=0xCF) && !matches!(marker, 0xC4 | 0xC8 | 0xCC);
                if is_sof {
                    return Some(be16(i + 5)? * be16(i + 7)?);
                }
                i += 2 + usize::try_from(be16(i + 2)?).ok()?;
            }
        }
        gpui::ImageFormat::Gif => gif_pixels(b),
        _ => None,
    }
}

/// GIF: logical screen size times the number of image descriptors (every frame decodes
/// to a full canvas).
fn gif_pixels(b: &[u8]) -> Option<u64> {
    let le16 = |i: usize| Some(u64::from(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?])));
    (b.get(..3)? == b"GIF").then_some(())?;
    let canvas = le16(6)? * le16(8)?;
    let table = |flags: u8| {
        if flags & 0x80 != 0 {
            3usize << ((flags & 7) + 1)
        } else {
            0
        }
    };
    let mut i = 13 + table(*b.get(10)?);
    // Skips data sub-blocks starting at `i`; returns the index after the terminator.
    let skip_blocks = |mut i: usize| -> Option<usize> {
        loop {
            let len = usize::from(*b.get(i)?);
            i += 1 + len;
            if len == 0 {
                return Some(i);
            }
        }
    };
    let mut frames = 0u64;
    loop {
        match *b.get(i)? {
            0x3B => return Some(canvas * frames.max(1)),
            0x21 => i = skip_blocks(i + 2)?,
            0x2C => {
                frames += 1;
                let flags = *b.get(i + 9)?;
                i = skip_blocks(i + 10 + table(flags) + 1)?;
            }
            _ => return None,
        }
    }
}

/// One toast for a drop that skipped entries: oversized files, folders, or both.
fn skipped_message(too_large: usize, not_files: usize) -> Option<String> {
    let big = match too_large {
        0 => None,
        1 => Some(TOO_LARGE.to_owned()),
        n => Some(format!("{n} files are larger than 100 MB")),
    };
    let other = match not_files {
        0 => None,
        1 => Some("1 item is not a file".to_owned()),
        n => Some(format!("{n} items are not files")),
    };
    match (big, other) {
        (Some(b), Some(o)) => Some(format!("Skipped: {b}; {o}")),
        (Some(b), None) => Some(b),
        (None, Some(_)) if not_files == 1 => Some("Only files can be attached".to_owned()),
        (None, Some(o)) => Some(format!("Only files can be attached ({o})")),
        (None, None) => None,
    }
}

/// UTF-8 without NUL bytes becomes a text preview; anything else is refused. The buffer
/// moves into the zeroizing `String` without a copy, or is wiped.
fn decode_text(mut bytes: Zeroizing<Vec<u8>>) -> ReadResult {
    if bytes.contains(&0) {
        return ReadResult::Unavailable("No preview: this file is not text.");
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(s) => ReadResult::Text(TextPreview::new(Zeroizing::new(s))),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            ReadResult::Unavailable("No preview: this file is not UTF-8 text.")
        }
    }
}

/// Streams the plaintext into a 0600 temp file next to `path`, fsyncs and renames it over
/// `path`. Returns `Ok(false)` if `cancel` was set (lock); the temp file is then deleted,
/// as on any error, so no partial plaintext is left under either name.
fn write_plain(reader: &mut dyn Read, path: &Path, cancel: &AtomicBool) -> io::Result<bool> {
    use rand::RngCore as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".vault-save-{:08x}.tmp",
        rand::rngs::OsRng.next_u32()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let result = (|| {
        let mut buf = Zeroizing::new(vec![0u8; COPY_CHUNK]);
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Ok(false);
            }
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
        }
        file.sync_all()?;
        Ok(true)
    })();
    drop(file);
    match result {
        Ok(true) => match std::fs::rename(&tmp, path) {
            Ok(()) => Ok(true),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        },
        other => {
            let _ = std::fs::remove_file(&tmp);
            other
        }
    }
}

#[cfg(test)]
pub mod fake {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// Keeps "blobs" in memory and records references through `UnlockedVault`, so the
    /// item side is real. `states` overrides `Present` per id.
    #[derive(Default)]
    pub struct FakeStore {
        pub blobs: Mutex<HashMap<Uuid, Vec<u8>>>,
        pub states: Mutex<HashMap<Uuid, AttachmentState>>,
    }

    impl FakeStore {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub fn set_state(&self, id: Uuid, state: AttachmentState) {
            self.states.lock().unwrap().insert(id, state);
        }
    }

    impl AttachmentStore for FakeStore {
        fn add(
            &self,
            vault: &mut SyncedVault,
            item: Uuid,
            name: &str,
            data: &mut dyn Read,
            size: u64,
            now: Millis,
        ) -> Result<Uuid, SyncError> {
            let mut bytes = Vec::new();
            data.read_to_end(&mut bytes)
                .map_err(|e| SyncError::Attachment(e.into()))?;
            if bytes.len() as u64 != size {
                return Err(AttachmentError::SizeMismatch {
                    expected: size,
                    actual: bytes.len() as u64,
                }
                .into());
            }
            let r = vault_core::attachment::new_ref(name, size, now)?;
            let id = r.id;
            vault.edit(|v| v.add_attachment_ref(item, r, now))??;
            self.blobs.lock().unwrap().insert(id, bytes);
            Ok(id)
        }

        fn open(
            &self,
            _vault: &SyncedVault,
            _item: Uuid,
            id: Uuid,
        ) -> Result<Box<dyn Read + Send>, SyncError> {
            let bytes = self
                .blobs
                .lock()
                .unwrap()
                .get(&id)
                .cloned()
                .ok_or(SyncError::AttachmentMissing(id))?;
            Ok(Box::new(io::Cursor::new(bytes)))
        }

        fn state(&self, _vault: &SyncedVault, id: Uuid) -> AttachmentState {
            if let Some(s) = self.states.lock().unwrap().get(&id) {
                return *s;
            }
            if self.blobs.lock().unwrap().contains_key(&id) {
                AttachmentState::Present
            } else {
                AttachmentState::Missing
            }
        }

        fn remove(
            &self,
            vault: &mut SyncedVault,
            item: Uuid,
            id: Uuid,
            now: Millis,
        ) -> Result<(), SyncError> {
            vault.edit(|v| v.remove_attachment_ref(item, id, now))??;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Arc;

    use gpui::{AppContext as _, Entity, TestAppContext};
    use vault_core::{ItemKind, KdfParams, SecretString};
    use vault_sync::NoopHooks;

    use super::fake::FakeStore;
    use super::*;
    use crate::state::Screen;

    const PW: &str = "pw";

    /// An unlocked vault on disk with two notes, the fake store, and the first note selected.
    fn setup(
        dir: &Path,
        store: Arc<dyn AttachmentStore>,
        cx: &mut TestAppContext,
    ) -> (Entity<AppState>, [Uuid; 2]) {
        let mut vault = SyncedVault::create(
            &dir.join("t.vault"),
            &SecretString::new(PW.into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let ids = vault
            .edit(|v| {
                let d = v.device_id();
                [
                    v.insert(Item::new(ItemKind::Note, "Alpha", d, 1), 1),
                    v.insert(Item::new(ItemKind::Note, "Beta", d, 1), 1),
                ]
            })
            .unwrap();
        vault.save().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, cx| {
            s.set_attachment_store(store);
            s.install_unlocked_for_tests(vault);
            s.select(ids[0], cx);
        });
        (state, ids)
    }

    fn file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn refs(state: &Entity<AppState>, item: Uuid, cx: &mut TestAppContext) -> Vec<(Uuid, String)> {
        state.read_with(cx, |s, _| {
            s.unlocked_vault()
                .and_then(|v| v.get(item))
                .map(|i| {
                    i.attachments
                        .iter()
                        .map(|a| (a.id, a.name.clone()))
                        .collect()
                })
                .unwrap_or_default()
        })
    }

    fn add(state: &Entity<AppState>, paths: Vec<PathBuf>, cx: &mut TestAppContext) {
        state.update(cx, |s, cx| s.add_attachment_files(paths, cx));
        cx.run_until_parked();
    }

    #[test]
    fn preview_only_for_listed_kinds() {
        let img = |f| Some(PreviewKind::Image(f));
        assert_eq!(preview_kind("a.png", 10), img(gpui::ImageFormat::Png));
        assert_eq!(preview_kind("A.JPG", 10), img(gpui::ImageFormat::Jpeg));
        assert_eq!(preview_kind("a.jpeg", 10), img(gpui::ImageFormat::Jpeg));
        assert_eq!(preview_kind("a.gif", 10), img(gpui::ImageFormat::Gif));
        assert_eq!(preview_kind("a.png", IMAGE_PREVIEW_MAX + 1), None);
        assert_eq!(preview_kind("notes.txt", 999_999), Some(PreviewKind::Text));
        assert_eq!(preview_kind("README", 10), Some(PreviewKind::Text));
        assert_eq!(
            preview_kind("notes.txt", TEXT_PREVIEW_MAX),
            None,
            "under 1 MB only"
        );
        for other in ["scan.heic", "a.pdf", "a.zip", "a.svg", "a.docx", "a.webp"] {
            assert_eq!(preview_kind(other, 10), None, "{other}");
        }
    }

    #[test]
    fn text_preview_lines() {
        let t = TextPreview::new(Zeroizing::new("one\r\ntwo\n\nfour".to_owned()));
        assert_eq!(t.line_count(), 4);
        assert_eq!(
            [t.line(0), t.line(1), t.line(2), t.line(3)],
            ["one", "two", "", "four"]
        );
        let long = "é".repeat(PREVIEW_LINE_MAX);
        let t = TextPreview::new(Zeroizing::new(long));
        assert!(t.line(0).len() <= PREVIEW_LINE_MAX);
        assert_eq!(
            TextPreview::new(Zeroizing::new(String::new())).line_count(),
            1
        );
    }

    #[gpui::test]
    fn add_files_then_remove_one(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::new();
        let (state, ids) = setup(dir.path(), store.clone(), cx);
        let a = file(dir.path(), "a.txt", b"hello");
        let b = file(dir.path(), "b.bin", &[1, 2, 3]);
        state.update(cx, |s, cx| {
            s.add_attachment_files(vec![a, b], cx);
            assert_eq!(s.busy, Some(Busy::Attaching));
            assert_eq!(s.attachments.pending.len(), 2, "rows with spinners");
            assert_eq!(
                s.shown_item().map(|i| i.id),
                Some(ids[0]),
                "held while sealing"
            );
        });
        cx.run_until_parked();
        let added = refs(&state, ids[0], cx);
        assert_eq!(
            added.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>(),
            ["a.txt", "b.bin"]
        );
        state.read_with(cx, |s, _| {
            assert!(s.busy.is_none() && s.attachments.pending.is_empty());
            assert!(!s.vault.as_ref().unwrap().is_dirty(), "the add saves");
            assert!(s.toast.is_none());
        });

        let gone = added[0].0;
        state.update(cx, |s, cx| {
            // Read mode: Remove is refused.
            s.request_remove_attachment(gone, cx);
            assert!(s.attachments.remove_confirm.is_none());
            s.confirm_remove_attachment(gone, cx);
            assert!(
                !s.vault.as_ref().unwrap().is_dirty(),
                "nothing removed in read mode"
            );
            s.begin_edit(cx);
            s.request_remove_attachment(gone, cx);
            assert_eq!(s.attachments.remove_confirm, Some(gone));
            s.confirm_remove_attachment(gone, cx);
            assert!(s.attachments.remove_confirm.is_none());
            assert!(s.vault.as_ref().unwrap().is_dirty(), "autosave pending");
        });
        assert_eq!(refs(&state, ids[0], cx), vec![added[1].clone()]);
        // Leaving edit mode drops a pending confirm.
        state.update(cx, |s, cx| {
            s.request_remove_attachment(added[1].0, cx);
            s.cancel_edit(cx);
            s.follow_attachment_selection(cx);
            assert!(s.attachments.remove_confirm.is_none());
        });
    }

    #[gpui::test]
    fn add_over_cap_refused_with_toast(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
        let big = dir.path().join("big.iso");
        // Sparse: no 100 MB actually written.
        std::fs::File::create(&big)
            .unwrap()
            .set_len(MAX_ATTACHMENT_SIZE + 1)
            .unwrap();
        let ok = file(dir.path(), "ok.txt", b"x");
        add(&state, vec![big.clone()], cx);
        state.read_with(cx, |s, _| {
            assert_eq!(
                s.toast.as_ref().map(|t| t.message.as_ref()),
                Some(TOO_LARGE)
            );
            assert!(s.busy.is_none());
        });
        assert!(refs(&state, ids[0], cx).is_empty());
        // Mixed: the big one is skipped, the other is added.
        add(&state, vec![big, ok], cx);
        assert_eq!(refs(&state, ids[0], cx).len(), 1);
    }

    #[gpui::test]
    fn lock_mid_add_discards_the_result(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::new();
        let (state, ids) = setup(dir.path(), store.clone(), cx);
        let a = file(dir.path(), "a.txt", b"hello");
        state.update(cx, |s, cx| {
            s.add_attachment_files(vec![a], cx);
            s.lock(cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.locked && s.busy.is_none());
            assert_eq!(s.screen, Screen::Unlock);
            assert!(s.toast.is_none(), "discarded silently");
            assert!(s.attachments.pending.is_empty());
            assert!(
                s.vault.as_ref().is_some_and(|v| v.vault().is_none()),
                "relocked"
            );
        });
        state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
        cx.run_until_parked();
        assert!(!state.read_with(cx, |s, _| s.locked));
        assert!(
            refs(&state, ids[0], cx).is_empty(),
            "the reference was taken out again"
        );
    }

    #[gpui::test]
    fn text_preview_is_wiped_on_selection_change_and_lock(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
        add(
            &state,
            vec![file(dir.path(), "notes.txt", b"line one\nline two")],
            cx,
        );
        let id = refs(&state, ids[0], cx)[0].0;
        let preview = |state: &Entity<AppState>, cx: &mut TestAppContext| {
            state.update(cx, |s, cx| s.toggle_attachment_preview(id, cx));
            cx.run_until_parked();
        };
        preview(&state, cx);
        state.read_with(cx, |s, _| {
            let p = s.attachments.preview.as_ref().expect("preview");
            let PreviewContent::Text(t) = &p.content else {
                panic!("not text")
            };
            assert_eq!((t.line(0), t.line(1)), ("line one", "line two"));
        });
        state.update(cx, |s, cx| {
            s.select(ids[1], cx);
            s.follow_attachment_selection(cx);
            assert!(s.attachments.preview.is_none(), "selection change wipes it");
            s.select(ids[0], cx);
        });
        preview(&state, cx);
        assert!(state.read_with(cx, |s, _| s.attachments.preview.is_some()));
        state.update(cx, |s, cx| s.lock(cx));
        assert!(state.read_with(cx, |s, _| s.attachments.preview.is_none()));
    }

    #[gpui::test]
    fn binary_named_txt_is_not_previewed(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
        add(
            &state,
            vec![file(dir.path(), "x.txt", &[0xff, 0xfe, 0, 1])],
            cx,
        );
        let id = refs(&state, ids[0], cx)[0].0;
        state.update(cx, |s, cx| s.toggle_attachment_preview(id, cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            let p = s.attachments.preview.as_ref().unwrap();
            assert!(matches!(p.content, PreviewContent::Unavailable(_)));
        });
    }

    #[gpui::test]
    fn missing_blob_refuses_preview(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::new();
        let (state, ids) = setup(dir.path(), store.clone(), cx);
        add(&state, vec![file(dir.path(), "a.txt", b"hi")], cx);
        let id = refs(&state, ids[0], cx)[0].0;
        store.blobs.lock().unwrap().clear();
        state.update(cx, |s, cx| {
            assert_eq!(s.attachment_state(id), AttachmentState::Missing);
            s.toggle_attachment_preview(id, cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.attachments.preview.is_none());
            assert_eq!(s.toast.as_ref().map(|t| t.message.as_ref()), Some(MISSING));
        });
    }

    #[gpui::test]
    fn save_copy_asks_first_and_writes_0600(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
        add(&state, vec![file(dir.path(), "a.txt", b"secret notes")], cx);
        let id = refs(&state, ids[0], cx)[0].0;
        let out = dir.path().join("out").join("a copy.txt");
        std::fs::create_dir(out.parent().unwrap()).unwrap();

        state.update(cx, |s, cx| s.save_attachment_to(id, out.clone(), cx));
        cx.run_until_parked();
        assert!(state.read_with(cx, |s, _| s.attachments.save_confirm.is_some()));
        assert!(!out.exists(), "nothing written before the confirm");

        state.update(cx, |s, cx| s.cancel_save_copy(cx));
        assert!(!out.exists());

        state.update(cx, |s, cx| {
            s.save_attachment_to(id, out.clone(), cx);
            s.confirm_save_copy(cx);
        });
        cx.run_until_parked();
        assert_eq!(std::fs::read(&out).unwrap(), b"secret notes");
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let names: Vec<_> = std::fs::read_dir(out.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "no temp file left: {names:?}");
        assert!(state.read_with(cx, |s, _| s.toast.is_some()));
    }

    #[gpui::test]
    fn lock_cancels_a_running_save(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids) = setup(dir.path(), FakeStore::new(), cx);
        add(&state, vec![file(dir.path(), "a.txt", b"secret")], cx);
        let id = refs(&state, ids[0], cx)[0].0;
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let target = out.join("a.txt");
        state.update(cx, |s, cx| {
            s.save_attachment_to(id, target.clone(), cx);
            s.confirm_save_copy(cx);
            s.lock(cx);
        });
        cx.run_until_parked();
        assert_eq!(
            std::fs::read_dir(&out).unwrap().count(),
            0,
            "no plaintext left"
        );
        assert!(state.read_with(cx, |s, _| s.toast.is_none()));
    }

    /// A fresh state reading the vault from disk.
    fn reopen(dir: &Path, cx: &mut TestAppContext) -> Entity<AppState> {
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let path = dir.join("t.vault");
        state.update(cx, |s, cx| s.open_vault(path, cx));
        cx.run_until_parked();
        state.update(cx, |s, cx| s.unlock(SecretString::new(PW.into()), cx));
        cx.run_until_parked();
        state
    }

    /// Two saved attachments; the first is then removed (autosave pending, vault dirty) and
    /// the second is evicted. Returns the ids `[removed, evicted]`.
    fn dirty_with_evicted(
        state: &Entity<AppState>,
        store: &FakeStore,
        dir: &Path,
        item: Uuid,
        cx: &mut TestAppContext,
    ) -> [Uuid; 2] {
        add(
            state,
            vec![file(dir, "gone.txt", b"1"), file(dir, "cloud.txt", b"2")],
            cx,
        );
        let ids = refs(state, item, cx);
        let (gone, cloud) = (ids[0].0, ids[1].0);
        store.set_state(cloud, AttachmentState::NotDownloaded);
        state.update(cx, |s, cx| {
            s.begin_edit(cx);
            s.confirm_remove_attachment(gone, cx);
            s.cancel_edit(cx);
            assert!(s.vault.as_ref().unwrap().is_dirty());
        });
        [gone, cloud]
    }

    #[gpui::test]
    fn lock_during_download_saves_pending_edits(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::new();
        let (state, ids) = setup(dir.path(), store.clone(), cx);
        let [_, cloud] = dirty_with_evicted(&state, &store, dir.path(), ids[0], cx);
        state.update(cx, |s, cx| {
            s.toggle_attachment_preview(cloud, cx);
            assert_eq!(
                s.busy,
                Some(Busy::ReadingAttachment),
                "vault moved for the download"
            );
            s.lock(cx);
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.locked && s.attachments.preview.is_none());
            assert!(
                s.vault.as_ref().is_some_and(|v| !v.is_dirty()),
                "saved, then locked"
            );
        });
        let fresh = reopen(dir.path(), cx);
        let names: Vec<_> = refs(&fresh, ids[0], cx)
            .into_iter()
            .map(|(_, n)| n)
            .collect();
        assert_eq!(names, ["cloud.txt"], "the Remove reached the file");
    }

    #[gpui::test]
    fn autosave_resumes_after_a_download(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::new();
        let (state, ids) = setup(dir.path(), store.clone(), cx);
        let [_, cloud] = dirty_with_evicted(&state, &store, dir.path(), ids[0], cx);
        state.update(cx, |s, cx| {
            s.toggle_attachment_preview(cloud, cx);
            // What a timer firing while the vault is in the task leaves behind.
            s.autosave = None;
            s.autosave_pending = false;
        });
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            assert!(s.attachments.preview.is_some());
            assert!(s.vault.as_ref().unwrap().is_dirty());
            assert!(s.autosave_pending, "autosave rescheduled");
        });
        cx.executor()
            .advance_clock(super::super::session::AUTOSAVE_DEBOUNCE * 2);
        cx.run_until_parked();
        assert!(state.read_with(cx, |s, _| !s.vault.as_ref().unwrap().is_dirty()));
    }

    #[test]
    fn image_headers_give_pixel_counts() {
        use gpui::ImageFormat::{Gif, Jpeg, Png};
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        png.extend_from_slice(&[0, 0, 0x27, 0x10, 0, 0, 0x13, 0x88]); // 10000 x 5000
        assert_eq!(image_pixels(Png, &png), Some(50_000_000));
        assert!(image_fits(Png, &png));
        png[19] = 0x11; // width 10001
        assert!(!image_fits(Png, &png));

        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0, 0];
        jpeg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 8, 0x00, 0x04, 0x00, 0x05]);
        assert_eq!(image_pixels(Jpeg, &jpeg), Some(20));

        // 2x3 canvas, no colour table, one extension, two frames.
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[2, 0, 3, 0, 0, 0, 0]);
        gif.extend_from_slice(&[0x21, 0xF9, 4, 0, 0, 0, 0, 0]);
        for _ in 0..2 {
            gif.extend_from_slice(&[0x2C, 0, 0, 0, 0, 2, 0, 3, 0, 0, 2, 1, 0x44, 0]);
        }
        gif.push(0x3B);
        assert_eq!(image_pixels(Gif, &gif), Some(12));

        assert_eq!(image_pixels(Png, b"not a png"), None);
        assert!(!image_fits(Gif, &gif[..20]), "truncated header is refused");
    }

    #[test]
    fn one_toast_for_skipped_drops() {
        assert_eq!(skipped_message(0, 0), None);
        assert_eq!(skipped_message(1, 0).as_deref(), Some(TOO_LARGE));
        assert_eq!(
            skipped_message(0, 1).as_deref(),
            Some("Only files can be attached")
        );
        assert_eq!(
            skipped_message(2, 3).as_deref(),
            Some("Skipped: 2 files are larger than 100 MB; 3 items are not files")
        );
    }

    /// The real vault-sync store end to end: seal, state, preview, missing blob.
    #[gpui::test]
    fn real_store_round_trip(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, ids) = setup(dir.path(), sync_store(), cx);
        add(&state, vec![file(dir.path(), "real.txt", b"from disk")], cx);
        let id = refs(&state, ids[0], cx)[0].0;
        assert_eq!(
            state.read_with(cx, |s, _| s.attachment_state(id)),
            AttachmentState::Present
        );
        state.update(cx, |s, cx| s.toggle_attachment_preview(id, cx));
        cx.run_until_parked();
        state.read_with(cx, |s, _| {
            let Some(PreviewContent::Text(t)) = s.attachments.preview.as_ref().map(|p| &p.content)
            else {
                panic!("no text preview")
            };
            assert_eq!(t.line(0), "from disk");
        });
        let blob = dir
            .path()
            .join("t.vault.attachments")
            .join(vault_core::attachment::blob_file_name(id));
        std::fs::remove_file(blob).unwrap();
        assert_eq!(
            state.read_with(cx, |s, _| s.attachment_state(id)),
            AttachmentState::Missing
        );
    }
}
