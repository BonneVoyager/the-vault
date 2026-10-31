//! Custom image icons (specs/05-ui.md §2.3 "Item icon picker"): the decoded-image cache
//! and the "Drop or choose image…" / drop flow.
//!
//! **Cache.** Each image icon's blob is decrypted and decoded once per unlock into a gpui
//! `RenderImage`, keyed by attachment id. `vault_changed` marks the cache for a rescan,
//! which the main screen runs on its next render ([`AppState::load_icon_images`]): ids no
//! item uses any more are dropped (and their images leave the sprite atlas), new ones whose
//! blob is on disk are decoded on the background executor. A blob that is not downloaded
//! or missing is not fetched; the tile shows the automatic icon until a later rescan finds
//! it. Stored blobs are decoded by `icon_image::decode_stored` (at most 256 KB and 256 px
//! per side, decoded under `image` limits, then handed to gpui as pixels). A blob that is
//! larger, unreadable or undecodable is not cached; its id is remembered as rejected for
//! the rest of the unlock and the tile shows the automatic icon. The cache holds at most
//! [`ICON_CACHE_CAP`] images; inserting past that evicts the least recently drawn one, and
//! a rescan never decodes into a full cache (so a vault with more image icons than that
//! does not thrash: the rest show the automatic icon). Lock and vault switch empty it.
//!
//! **Adding.** The chosen file is checked, scaled and re-encoded (`crate::icon_image`) and
//! sealed through the ordinary attachment-add path (`AttachmentStore::add`, the same
//! `run_bg` task shape as "Add file…"), so the reference is on the stored item at once,
//! while `icon` changes only in the edit buffer. The buffer remembers the ids it added.
//! Save writes the icon and, in the same vault edit, removes the references the item no
//! longer uses: the previous image (replace, or a switch to Automatic, a symbol or a
//! colour) and images added and replaced again in this edit. Cancel, a guard that ends the
//! edit, and lock remove the references this edit added, exactly like an add whose result
//! arrives after a lock: the reference goes and the sealed blob stays on disk until vault-
//! sync's orphan cleanup deletes it (24 h after its mtime, once no item references it).
//! When the vault is inside a background task at that moment, the removals are queued
//! and done as soon as it is back.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use gpui::{Context, RenderImage};
use vault_core::Uuid;
use vault_sync::AttachmentState;

use super::{AppState, Busy, Mode, Outcome};
use crate::icon::{self, PickerCell, PickerCursor};
use crate::icon_image::{self, Refusal};
use crate::text;

/// Most decoded icon images kept (128 px RGBA is 64 KB, so about 8 MB).
pub const ICON_CACHE_CAP: usize = 128;

#[derive(Clone)]
enum Entry {
    /// Decrypting and decoding on the background executor.
    Loading,
    Ready(Arc<RenderImage>),
}

struct Cached {
    entry: Entry,
    /// `IconImages::clock` when last drawn (or inserted): the LRU order.
    used: Cell<u64>,
}

/// Decoded image icons of the unlocked vault and the references waiting to be dropped.
pub struct IconImages {
    entries: HashMap<Uuid, Cached>,
    /// Ids whose blob was too large, unreadable or undecodable this unlock: not cached,
    /// not retried until the next unlock.
    rejected: HashSet<Uuid>,
    /// Use counter for the LRU order (bumped by drawing, through `&self`).
    clock: Cell<u64>,
    /// Most entries kept ([`ICON_CACHE_CAP`]; tests lower it).
    pub(crate) cap: usize,
    /// Bumped by `clear`; a decode started under an older ticket is dropped.
    ticket: u64,
    /// The vault changed since the last scan.
    dirty: bool,
    /// `(item, attachment)` references to remove once the vault is back from a task.
    pub(super) drops: Vec<(Uuid, Uuid)>,
    /// Blob decodes started (tests count them).
    pub(crate) decodes: usize,
}

impl Default for IconImages {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            rejected: HashSet::new(),
            clock: Cell::new(0),
            cap: ICON_CACHE_CAP,
            ticket: 0,
            dirty: true,
            drops: Vec::new(),
            decodes: 0,
        }
    }
}

impl IconImages {
    /// Marks the cache for a rescan on the next render.
    pub fn invalidate(&mut self) {
        self.dirty = true;
    }

    /// Whether attachment `id` is cached (ready or loading).
    #[cfg(test)]
    pub fn is_cached(&self, id: Uuid) -> bool {
        self.entries.contains_key(&id)
    }

    /// Whether attachment `id` was refused this unlock.
    #[cfg(test)]
    pub fn is_rejected(&self, id: Uuid) -> bool {
        self.rejected.contains(&id)
    }

    fn tick(&self) -> u64 {
        let t = self.clock.get() + 1;
        self.clock.set(t);
        t
    }

    /// Stores a decoded image, evicting the least recently drawn ready images while over
    /// the cap. Returns the evicted images (for the sprite atlas).
    fn insert_ready(&mut self, id: Uuid, image: Arc<RenderImage>) -> Vec<Arc<RenderImage>> {
        let used = Cell::new(self.tick());
        self.rejected.remove(&id);
        self.entries.insert(
            id,
            Cached {
                entry: Entry::Ready(image),
                used,
            },
        );
        let mut evicted = Vec::new();
        while self.entries.len() > self.cap {
            let lru = self
                .entries
                .iter()
                .filter(|(k, c)| **k != id && matches!(c.entry, Entry::Ready(_)))
                .min_by_key(|(_, c)| c.used.get())
                .map(|(k, _)| *k);
            let Some(lru) = lru else { break };
            if let Some(Cached {
                entry: Entry::Ready(image),
                ..
            }) = self.entries.remove(&lru)
            {
                evicted.push(image);
            }
        }
        evicted
    }

    fn reject(&mut self, id: Uuid) {
        self.entries.remove(&id);
        self.rejected.insert(id);
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl AppState {
    /// The decoded image of icon attachment `id`, when ready.
    /// Drawing it counts as a use for the LRU order.
    pub fn icon_image(&self, id: Uuid) -> Option<Arc<RenderImage>> {
        let ui = &self.icon_images;
        match ui.entries.get(&id) {
            Some(Cached {
                entry: Entry::Ready(image),
                used,
            }) => {
                used.set(ui.tick());
                Some(image.clone())
            }
            _ => None,
        }
    }

    /// Takes images out of every window's sprite atlas.
    fn evict_icon_images(images: Vec<Arc<RenderImage>>, cx: &mut Context<Self>) {
        for image in images {
            cx.defer(move |cx| cx.drop_image(image, None));
        }
    }

    /// The attachment ids image icons point at now, each with its item: every live item's
    /// stored icon, plus the edit buffer's (an image chosen in this edit), provided the
    /// stored item still carries that reference.
    fn wanted_icon_images(&self) -> HashMap<Uuid, (Uuid, u64)> {
        let mut wanted = HashMap::new();
        let Some(vault) = self.unlocked_vault() else {
            return wanted;
        };
        let mut add = |item: &vault_core::Item, icon: Option<&vault_core::ItemIcon>| {
            if let Some(id) = icon.and_then(icon::image_attachment)
                && let Some(r) = item.attachment(id)
            {
                wanted.insert(id, (item.id, r.size));
            }
        };
        for item in vault.items().filter(|i| !i.is_deleted()) {
            add(item, item.icon.as_ref());
        }
        if let Some(b) = self.edit_buffer()
            && let Some(stored) = vault.get(b.item.id)
        {
            add(stored, b.item.icon.as_ref());
        }
        wanted
    }

    /// Rescans after a vault change (called by the main screen while rendering): drops
    /// queued references, forgets images no item uses, starts decoding new ones.
    pub fn load_icon_images(&mut self, cx: &mut Context<Self>) {
        if self.locked || self.vault.is_none() {
            return;
        }
        if !self.icon_images.drops.is_empty() {
            self.flush_icon_drops(cx);
        }
        if !self.icon_images.dirty {
            return;
        }
        self.icon_images.dirty = false;
        let wanted = self.wanted_icon_images();
        let stale: Vec<Uuid> = self
            .icon_images
            .entries
            .keys()
            .filter(|id| !wanted.contains_key(id))
            .copied()
            .collect();
        for id in stale {
            if let Some(Cached {
                entry: Entry::Ready(image),
                ..
            }) = self.icon_images.entries.remove(&id)
            {
                Self::evict_icon_images(vec![image], cx);
            }
        }
        self.icon_images
            .rejected
            .retain(|id| wanted.contains_key(id));
        for (id, (item, size)) in wanted {
            let ui = &self.icon_images;
            if ui.entries.len() >= ui.cap {
                // Full: never evict for a rescan (no thrash); the rest stay automatic.
                break;
            }
            if !ui.entries.contains_key(&id) && !ui.rejected.contains(&id) {
                self.start_icon_decode(item, id, size, cx);
            }
        }
    }

    fn start_icon_decode(&mut self, item: Uuid, id: Uuid, size: u64, cx: &mut Context<Self>) {
        if self.attachment_state(id) != AttachmentState::Present {
            // Not downloaded or missing: no download from a render; automatic meanwhile.
            return;
        }
        if size > icon_image::STORED_MAX_BYTES {
            // Not an icon this app wrote: refused without reading it.
            self.icon_images.reject(id);
            return;
        }
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        let reader = match self.attach_store.open(vault, item, id) {
            Ok(reader) => reader,
            Err(_) => {
                self.icon_images.reject(id);
                return;
            }
        };
        let used = Cell::new(self.icon_images.tick());
        self.icon_images.entries.insert(
            id,
            Cached {
                entry: Entry::Loading,
                used,
            },
        );
        self.icon_images.decodes += 1;
        let ticket = self.icon_images.ticket;
        let task = cx
            .background_executor()
            .spawn(async move { decode_stored(reader, size) });
        cx.spawn(async move |this, cx| {
            let image = task.await;
            this.update(cx, |this, cx| {
                let ui = &mut this.icon_images;
                let loading = matches!(
                    ui.entries.get(&id),
                    Some(Cached {
                        entry: Entry::Loading,
                        ..
                    })
                );
                if ui.ticket != ticket || !loading {
                    if let Some(image) = image {
                        Self::evict_icon_images(vec![image], cx);
                    }
                    return;
                }
                match image {
                    Some(image) => {
                        let evicted = ui.insert_ready(id, image);
                        Self::evict_icon_images(evicted, cx);
                    }
                    None => ui.reject(id),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Lock / vault switch: forget every decoded image and take them out of the atlas.
    pub(super) fn clear_icon_images(&mut self, cx: &mut Context<Self>) {
        let ui = &mut self.icon_images;
        ui.ticket = ui.ticket.wrapping_add(1);
        ui.dirty = true;
        ui.rejected.clear();
        let images = ui
            .entries
            .drain()
            .filter_map(|(_, c)| match c.entry {
                Entry::Ready(image) => Some(image),
                Entry::Loading => None,
            })
            .collect();
        Self::evict_icon_images(images, cx);
    }

    /// Forgets queued reference removals (the vault they belong to is gone).
    pub(super) fn forget_icon_drops(&mut self) {
        self.icon_images.drops.clear();
    }

    /// Takes attachment references `ids` out of `item` again (now, or as soon as the vault
    /// is back from a task). The blobs go with orphan cleanup.
    pub(super) fn drop_icon_refs(&mut self, item: Uuid, ids: Vec<Uuid>, cx: &mut Context<Self>) {
        if ids.is_empty() {
            return;
        }
        self.icon_images
            .drops
            .extend(ids.into_iter().map(|id| (item, id)));
        self.flush_icon_drops(cx);
    }

    /// Removes the queued references if the vault is here and unlocked. References a merge
    /// or another path already removed are skipped.
    pub(super) fn flush_icon_drops(&mut self, cx: &mut Context<Self>) {
        if self.locked || self.vault.is_none() || self.icon_images.drops.is_empty() {
            return;
        }
        let drops = std::mem::take(&mut self.icon_images.drops);
        let now = text::now_millis();
        let mut removed = false;
        for (item, id) in drops {
            let present = self
                .unlocked_vault()
                .and_then(|v| v.get(item))
                .is_some_and(|i| i.attachment(id).is_some());
            let Some(vault) = self.vault.as_mut() else {
                return;
            };
            if present && self.attach_store.remove(vault, item, id, now).is_ok() {
                removed = true;
            }
        }
        if removed {
            self.vault_changed();
            self.schedule_autosave(cx);
        }
    }

    /// Whether "Drop or choose image…" and drops on the tile work now: editing an item that is in
    /// the vault (a new item has nowhere to attach the blob yet), no task running.
    pub fn can_choose_icon_image(&self) -> bool {
        matches!(self.mode, Mode::Edit(_)) && self.can_attach() && self.busy.is_none()
    }

    /// "Drop or choose image…": the open panel, then [`Self::set_icon_image_file`].
    pub fn pick_icon_image(&mut self, cx: &mut Context<Self>) {
        if !self.can_choose_icon_image() {
            return;
        }
        let (lock_gen, epoch, session) = (self.lock_gen, self.epoch, self.edit_session);
        let rx = cx.prompt_for_paths(gpui::PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Choose".into()),
        });
        cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(paths))) = rx.await else {
                return;
            };
            this.update(cx, |this, cx| {
                let same = this.lock_gen == lock_gen
                    && this.epoch == epoch
                    && this.edit_session == session;
                if same && let Some(path) = paths.into_iter().next() {
                    this.set_icon_image_file(path, cx);
                }
            })
            .ok();
        })
        .detach();
    }

    /// Uses the image at `path` as the edited item's icon (open panel or drop on the tile).
    /// Refused with a toast when it is over 512 KB, not a readable PNG or JPEG, or larger
    /// than 8192 px on a side.
    pub fn set_icon_image_file(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        if !matches!(self.mode, Mode::Edit(_)) || !self.can_attach() {
            return;
        }
        if self.busy.is_some() {
            self.show_toast("Wait for the current task to finish", cx);
            return;
        }
        let Some(item) = self.edit_buffer().map(|b| b.item.id) else {
            return;
        };
        match std::fs::metadata(&path) {
            Ok(m) if m.is_file() && m.len() > icon_image::MAX_INPUT_BYTES => {
                return self.show_toast(Refusal::TooLarge.message(), cx);
            }
            Ok(m) if m.is_file() => {}
            _ => return self.show_toast(Refusal::Unreadable.message(), cx),
        }
        self.hold_selected();
        let Some(mut vault) = self.vault.take() else {
            self.attachments.held = None;
            return;
        };
        if let Some(b) = self.edit_buffer_mut() {
            b.icon_loading = true;
        }
        let session = self.edit_session;
        let store = self.attach_store.clone();
        let now = text::now_millis();
        self.run_bg_cx(
            Busy::Attaching,
            cx,
            move || {
                let result = read_and_prepare(&path).and_then(|png| {
                    let image = icon_image::decode_stored(&png).ok().map(render_image);
                    let size = png.len() as u64;
                    store
                        .add(
                            &mut vault,
                            item,
                            icon_image::ATTACHMENT_NAME,
                            &mut Cursor::new(png),
                            size,
                            now,
                        )
                        .map(|id| (id, image))
                        .map_err(|e| format!("Could not add the image: {e}"))
                });
                (vault, store, result)
            },
            move |this, (mut vault, store, result), outcome, cx| {
                this.attachments.held = None;
                let editing = this.edit_session == session
                    && matches!(&this.mode, Mode::Edit(b) if b.item.id == item);
                if let Some(b) = this.edit_buffer_mut() {
                    b.icon_loading = false;
                }
                if outcome != Outcome::Fresh || !editing {
                    // Like an add cancelled by a lock: take the reference out again.
                    if let Ok((id, image)) = result {
                        let _ = store.remove(&mut vault, item, id, now);
                        if let Some(image) = image {
                            cx.defer(move |cx| cx.drop_image(image, None));
                        }
                    }
                    this.return_vault(vault, outcome, cx);
                    if outcome == Outcome::Fresh {
                        this.vault_changed();
                    }
                    return;
                }
                this.vault = Some(vault);
                match result {
                    Ok((id, image)) => {
                        if let Some(image) = image {
                            let evicted = this.icon_images.insert_ready(id, image);
                            Self::evict_icon_images(evicted, cx);
                        }
                        if let Some(b) = this.edit_buffer_mut() {
                            b.icon_added.push(id);
                            b.item.icon = Some(icon::image_icon(id));
                            b.error = None;
                            if let Some(cursor) = b.icon_picker.as_mut() {
                                *cursor = PickerCursor::at(PickerCell::Image);
                            }
                        }
                        this.vault_changed();
                    }
                    Err(message) => this.show_toast(message, cx),
                }
                this.resume_autosave(cx);
            },
        );
    }
}

/// Background: the chosen file, checked and turned into the stored PNG.
fn read_and_prepare(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let refuse = |r: Refusal| r.message().to_owned();
    let file = std::fs::File::open(path).map_err(|_| refuse(Refusal::Unreadable))?;
    let mut bytes = Vec::new();
    // One byte past the limit is enough to know it is too large.
    file.take(icon_image::MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse(Refusal::Unreadable))?;
    icon_image::prepare(&bytes).map_err(refuse)
}

/// Background: a stored icon blob decrypted and decoded, or `None` when it cannot be
/// read or `icon_image::decode_stored` refuses it (too large, over 256 px, not a PNG or
/// JPEG). The decode runs under `image` limits; gpui only receives the pixels.
fn decode_stored(mut reader: Box<dyn std::io::Read + Send>, size: u64) -> Option<Arc<RenderImage>> {
    if size > icon_image::STORED_MAX_BYTES {
        return None;
    }
    let never = AtomicBool::new(false);
    let bytes = super::attachments::read_all(&mut *reader, size, &never).ok()??;
    icon_image::decode_stored(&bytes).ok().map(render_image)
}

/// RGBA pixels as a gpui image (gpui stores BGRA, like its own decoder).
fn render_image(mut rgba: image::RgbaImage) -> Arc<RenderImage> {
    for px in rgba.as_chunks_mut::<4>().0 {
        px.swap(0, 2);
    }
    Arc::new(RenderImage::new(vec![image::Frame::new(rgba)]))
}

/// Ids in `a` but not in `b`, in `a`'s order, without repeats.
pub(super) fn minus(a: impl IntoIterator<Item = Uuid>, keep: Option<Uuid>) -> Vec<Uuid> {
    let mut seen = HashSet::new();
    a.into_iter()
        .filter(|id| Some(*id) != keep && seen.insert(*id))
        .collect()
}

#[cfg(test)]
#[path = "icon_images_tests.rs"]
mod tests;
