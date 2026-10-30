//! Edit mode, new items, delete and the unsaved-changes guard (specs/05-ui.md §2.3, §3).
//!
//! The `EditBuffer` lives in `AppState::mode` and is the single source of truth while
//! editing: the editor view writes every keystroke into it as a `SecretString`, and the
//! global ⌘S handler saves it without needing the view. Field values never leave
//! `SecretString` here.

use gpui::{Context, SharedString};
use vault_core::{
    ExposeSecret, Field, FieldKind, HistoryEntry, Item, Millis, SecretString, Totp, UnlockedVault,
    Uuid, VaultError,
};

use super::{AppState, ChooseIntent, Filter, FocusTarget, Mode};
use crate::templates::Template;
use crate::text;

/// A plain clone of the item being edited, plus what the editor needs to track rows.
#[derive(Debug, Clone)]
pub struct EditBuffer {
    /// Title and fields are edited in place; everything else is carried through.
    pub item: Item,
    /// The item as it was when editing began (the template for a new item).
    original: Item,
    /// Stable per-row keys, parallel to `item.fields`; the view keys its inputs by them.
    pub keys: Vec<u64>,
    next_key: u64,
    /// Inline validation or save error ("Title required").
    pub error: Option<SharedString>,
    /// Rows whose value was set from outside the editor (generator "Use"); the view
    /// copies these into its inputs and clears the list.
    pub pushed: Vec<u64>,
    /// Rows the user touched that also changed on another device ("changed remotely").
    pub remote_fields: Vec<u64>,
    /// Same for the title.
    pub remote_title: bool,
    /// Text in the tag input not yet committed with Enter or a comma; Save commits it.
    pub tag_draft: String,
    /// `replaced_at` stamps of password-history entries the user removed in this edit.
    /// Applied on Save (core `remove_history_entry`), dropped on Cancel.
    pub removed_history: Vec<Millis>,
}

impl EditBuffer {
    pub fn new(item: Item) -> Self {
        let keys = (0..item.fields.len() as u64).collect();
        Self {
            next_key: item.fields.len() as u64,
            original: item.clone(),
            item,
            keys,
            error: None,
            pushed: Vec::new(),
            remote_fields: Vec::new(),
            remote_title: false,
            tag_draft: String::new(),
            removed_history: Vec::new(),
        }
    }

    /// Password-history entries still shown: the item's history minus pending removals.
    pub fn history(&self) -> impl Iterator<Item = &HistoryEntry> {
        self.item
            .history
            .iter()
            .filter(|h| !self.removed_history.contains(&h.replaced_at))
    }

    /// Trash button on a history entry: marks the entry with `replaced_at` for removal.
    pub fn remove_history(&mut self, replaced_at: Millis) {
        let known = self
            .item
            .history
            .iter()
            .any(|h| h.replaced_at == replaced_at);
        if known && !self.removed_history.contains(&replaced_at) {
            self.removed_history.push(replaced_at);
        }
    }

    /// "Clear history": marks every entry shown when editing began for removal. Entries
    /// another device adds meanwhile are not touched.
    pub fn clear_history(&mut self) {
        let mut stamps: Vec<Millis> = self.history().map(|h| h.replaced_at).collect();
        // Two merged entries can share a stamp; core removes them together.
        stamps.sort_unstable();
        stamps.dedup();
        self.removed_history.extend(stamps);
    }

    /// Recomputes the "changed remotely" marks against `stored`, the item as it is in the
    /// vault after a merge. A row is marked when the user changed it here and the stored
    /// field (looked up by its name when editing began) no longer matches `original`.
    pub fn mark_remote(&mut self, stored: &Item) {
        let original = &self.original;
        self.remote_fields = self
            .keys
            .iter()
            .zip(&self.item.fields)
            .filter_map(|(key, field)| {
                let of = usize::try_from(*key)
                    .ok()
                    .and_then(|k| original.fields.get(k))?;
                let touched = !same_field(field, of);
                let remote = stored.field(&of.name).is_none_or(|sf| !same_field(sf, of));
                (touched && remote).then_some(*key)
            })
            .collect();
        self.remote_title = self.item.title != original.title && stored.title != original.title;
    }

    /// Index of the row with `key`.
    pub fn index(&self, key: u64) -> Option<usize> {
        self.keys.iter().position(|k| *k == key)
    }

    pub fn field(&self, key: u64) -> Option<&Field> {
        self.index(key).map(|i| &self.item.fields[i])
    }

    fn field_mut(&mut self, key: u64) -> Option<&mut Field> {
        self.index(key).map(|i| &mut self.item.fields[i])
    }

    /// True when title, tags or fields differ from where editing started.
    pub fn has_changes(&self) -> bool {
        self.item.title != self.original.title
            || self.item.tags != self.original.tags
            || self.draft_adds_tag()
            || !self.removed_history.is_empty()
            || self.item.fields.len() != self.original.fields.len()
            || self
                .item
                .fields
                .iter()
                .zip(&self.original.fields)
                .any(|(a, b)| !same_field(a, b))
    }

    /// Appends a field of `kind` with a unique default name; returns its key.
    pub fn add_field(&mut self, kind: FieldKind) -> u64 {
        // Field names stay lower case, like the template names ("password", "url").
        let base = kind_name(kind).to_lowercase();
        let mut name = base.clone();
        let mut n = 2;
        while self.item.fields.iter().any(|f| f.name == name) {
            name = format!("{base} {n}");
            n += 1;
        }
        let key = self.next_key;
        self.next_key += 1;
        // modified_at 0 = "new"; the save stamps it.
        self.item
            .fields
            .push(Field::new(name, kind, SecretString::new(String::new()), 0));
        self.keys.push(key);
        key
    }

    pub fn remove_field(&mut self, key: u64) {
        if let Some(i) = self.index(key) {
            self.item.fields.remove(i);
            self.keys.remove(i);
        }
    }

    /// Moves the row `key` to position `to` (clamped).
    pub fn move_field(&mut self, key: u64, to: usize) {
        let Some(from) = self.index(key) else {
            return;
        };
        let to = to.min(self.keys.len() - 1);
        let field = self.item.fields.remove(from);
        let k = self.keys.remove(from);
        self.item.fields.insert(to, field);
        self.keys.insert(to, k);
    }

    /// Adds a tag typed by the user: trimmed, leading `#` stripped. Blank tags and
    /// case-insensitive duplicates are ignored. Returns true if the tag was added.
    pub fn add_tag(&mut self, raw: &str) -> bool {
        push_tag(&mut self.item.tags, raw)
    }

    pub fn remove_tag(&mut self, ix: usize) {
        if ix < self.item.tags.len() {
            self.item.tags.remove(ix);
        }
    }

    /// Takes the tag input's text as the draft. Every comma-terminated part is committed
    /// as a tag; returns the text after the last comma when there was one (the input
    /// should then show just that).
    pub fn type_tags(&mut self, text: &str) -> Option<String> {
        let Some((done, rest)) = text.rsplit_once(',') else {
            self.tag_draft = text.to_owned();
            return None;
        };
        for part in done.split(',') {
            self.add_tag(part);
        }
        self.tag_draft = rest.to_owned();
        Some(rest.to_owned())
    }

    /// True when committing the draft would add a tag (not blank, not a duplicate).
    fn draft_adds_tag(&self) -> bool {
        normalize_tag(&self.tag_draft)
            .is_some_and(|d| !crate::templates::has_tag(&self.item.tags, &d))
    }

    /// Enter in the tag input: commits the draft.
    pub fn commit_tag_draft(&mut self) {
        let draft = std::mem::take(&mut self.tag_draft);
        self.add_tag(&draft);
    }

    /// Parse status shown under one-time-code row `key`: `(valid, message)`. `None` for
    /// other rows and for an empty value.
    pub fn totp_hint(&self, key: u64) -> Option<(bool, &'static str)> {
        let field = self.field(key).filter(|f| f.kind == FieldKind::Totp)?;
        let raw = field.value.expose_secret().trim();
        if raw.is_empty() {
            return None;
        }
        Some(if Totp::parse_uri(raw).is_ok() {
            (true, TOTP_VALID)
        } else if !looks_like_uri(raw) && Totp::from_secret_base32(raw).is_ok() {
            (true, TOTP_VALID_SECRET)
        } else {
            (false, TOTP_INVALID)
        })
    }

    /// Validates and returns the item to write: trimmed title, names and tags, a pending
    /// tag committed, and one-time-code values stored as `otpauth://` URIs (01 §4).
    fn finished(&self) -> Result<Item, SharedString> {
        let mut item = self.item.clone();
        item.title = item.title.trim().to_owned();
        if item.title.is_empty() {
            return Err("Title required".into());
        }
        push_tag(&mut item.tags, &self.tag_draft);
        // Only rows the user added or changed: an untouched field must stay byte-identical,
        // or `apply_edit` would see a change and overwrite a value merged in meanwhile.
        for (key, f) in self.keys.iter().zip(item.fields.iter_mut()) {
            let untouched = usize::try_from(*key)
                .ok()
                .and_then(|k| self.original.fields.get(k))
                .is_some_and(|of| same_field(f, of));
            if f.kind != FieldKind::Totp || untouched {
                continue;
            }
            f.value = normalize_totp(&f.value, &item.title);
        }
        for i in 0..item.fields.len() {
            let name = item.fields[i].name.trim().to_owned();
            if name.is_empty() {
                return Err("Every field needs a name".into());
            }
            if item.fields[..i].iter().any(|f| f.name == name) {
                return Err(format!("Two fields are named \u{201c}{name}\u{201d}").into());
            }
            item.fields[i].name = name;
        }
        Ok(item)
    }
}

/// Status lines under a one-time-code field in the editor.
const TOTP_VALID: &str = "Valid one-time code";
const TOTP_VALID_SECRET: &str = "Valid one-time code secret (saved as an otpauth:// URI)";
const TOTP_INVALID: &str = "Not a valid otpauth URI or base32 secret";

/// A typed tag, trimmed and without leading `#`; `None` when nothing is left.
fn normalize_tag(raw: &str) -> Option<String> {
    let tag = raw.trim().trim_start_matches('#').trim();
    (!tag.is_empty()).then(|| tag.to_owned())
}

/// Appends `raw` to `tags` unless it is blank or already there (case-insensitively).
fn push_tag(tags: &mut Vec<String>, raw: &str) -> bool {
    let Some(tag) = normalize_tag(raw) else {
        return false;
    };
    if crate::templates::has_tag(tags, &tag) {
        return false;
    }
    tags.push(tag);
    true
}

/// True when `s` starts like a URI (`scheme:`), so it is never taken for a bare secret.
fn looks_like_uri(s: &str) -> bool {
    s.split_once(':').is_some_and(|(scheme, _)| {
        !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    })
}

/// The value to store for a one-time-code field: trimmed; a bare base32 secret becomes
/// `otpauth://totp/<title>?secret=…`. Anything else (a URI, or text that parses as
/// neither) is stored trimmed as typed; the editor flags it.
fn normalize_totp(value: &SecretString, title: &str) -> SecretString {
    let raw = value.expose_secret().trim();
    if looks_like_uri(raw) || raw.is_empty() {
        return SecretString::new(raw.to_owned());
    }
    let Ok(totp) = Totp::from_secret_base32(raw) else {
        return SecretString::new(raw.to_owned());
    };
    // `to_uri` has an empty label for a bare secret; put the item title there.
    let uri = totp.to_uri();
    let query = uri.expose_secret().split_once('?').map_or("", |(_, q)| q);
    let label = percent_encode(title);
    let mut out = String::with_capacity(16 + label.len() + query.len());
    out.push_str("otpauth://totp/");
    out.push_str(&label);
    out.push('?');
    out.push_str(query);
    SecretString::new(out)
}

/// Percent-encodes everything but RFC 3986 unreserved characters (for the URI label).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(super) fn same_field(a: &Field, b: &Field) -> bool {
    a.name == b.name && a.kind == b.kind && a.value.expose_secret() == b.value.expose_secret()
}

/// User-facing label of a field kind ("Add field" menu and the chip next to a field).
pub fn kind_name(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Text => "Text",
        FieldKind::Password => "Password",
        FieldKind::Totp => "One-time code",
        FieldKind::Url => "URL",
        FieldKind::Notes => "Notes",
        FieldKind::Email => "Email",
        FieldKind::Date => "Date",
        FieldKind::MonthYear => "Month/year",
        FieldKind::Other => FieldKind::Other.as_str(),
    }
}

/// The kinds the "Add field" menu offers, in menu order. Unknown kinds are never offered.
pub const ADDABLE_KINDS: [FieldKind; 8] = [
    FieldKind::Text,
    FieldKind::Password,
    FieldKind::Totp,
    FieldKind::Url,
    FieldKind::Notes,
    FieldKind::Email,
    FieldKind::Date,
    FieldKind::MonthYear,
];

/// Where the user was going when the unsaved-changes guard stopped them.
#[derive(Debug, Clone, PartialEq)]
pub enum Navigation {
    Select(Uuid),
    Offset(isize),
    Filter(Filter),
    New(Template, String),
    Edit,
    SwitchVault(ChooseIntent),
    /// "Restore…" in Settings ▸ Sync & Backup.
    Restore(std::path::PathBuf),
    /// A Settings ▸ Security operation; "Discard" reopens that tab.
    Security,
}

/// Writes an edit over the stored item, touching only what the user changed.
///
/// The buffer is diffed against `original` (the item as editing began), row by row via
/// the row keys: key `k < original.fields.len()` started life as `original.fields[k]`.
/// Untouched fields keep whatever the stored item has now, so a change merged in while
/// editing survives. Changed fields start from the stored field (keeping its extras),
/// with the stored stamp if the name is unchanged so `update`'s diff bumps exactly them;
/// a renamed or added field counts as new. Fields added to the stored item meanwhile are
/// kept; fields the user removed are dropped.
///
/// A changed password goes through `set_field` first, under its original name, so the old
/// value lands in the history even when the field was also renamed (02 `set_field`).
fn apply_edit(
    v: &mut UnlockedVault,
    item: Item,
    keys: &[u64],
    original: &Item,
    now: u64,
) -> Result<Uuid, VaultError> {
    let id = item.id;
    let source = |key: u64| {
        usize::try_from(key)
            .ok()
            .and_then(|k| original.fields.get(k))
    };
    for (key, f) in keys.iter().zip(&item.fields) {
        let Some(of) = source(*key) else { continue };
        let changed_password = of.kind == FieldKind::Password
            && f.kind == FieldKind::Password
            && of.value.expose_secret() != f.value.expose_secret();
        let stored_password = v
            .get(id)
            .and_then(|it| it.field(&of.name))
            .is_some_and(|s| s.kind == FieldKind::Password);
        if changed_password && stored_password {
            v.set_field(id, &of.name, f.value.clone(), now)?;
        }
    }
    let title_changed = item.title != original.title;
    let tags_changed = item.tags != original.tags;
    v.update(id, now, |it| {
        if title_changed {
            it.title = item.title;
        }
        if tags_changed {
            it.tags = item.tags;
        }
        let mut stored = std::mem::take(&mut it.fields);
        let mut fields = Vec::with_capacity(item.fields.len());
        for (key, bf) in keys.iter().zip(item.fields) {
            let Some(of) = source(*key) else {
                fields.push(Field {
                    modified_at: 0,
                    ..bf
                });
                continue;
            };
            let unchanged = same_field(&bf, of);
            let renamed = bf.name != of.name;
            let sf = stored
                .iter()
                .position(|s| s.name == of.name)
                .map(|p| stored.remove(p));
            if unchanged {
                // Removed remotely while untouched here: stays removed.
                fields.extend(sf);
                continue;
            }
            let mut f = match sf {
                Some(s) => Field {
                    name: bf.name,
                    kind: bf.kind,
                    value: bf.value,
                    ..s
                },
                None => Field {
                    modified_at: 0,
                    ..bf
                },
            };
            if renamed {
                f.modified_at = 0;
            }
            fields.push(f);
        }
        // Added to the stored item meanwhile (not in the original): keep.
        fields.extend(
            stored
                .into_iter()
                .filter(|s| !original.fields.iter().any(|o| o.name == s.name)),
        );
        it.fields = fields;
    })?;
    Ok(id)
}

/// Removes the history entries stamped `removed` from item `id`, one core call each.
/// A stamp no longer in the stored history (removed by a merge meanwhile) is skipped:
/// core rejects it, and the entry is already gone.
fn remove_history(
    v: &mut UnlockedVault,
    id: Uuid,
    removed: &[Millis],
    now: u64,
) -> Result<(), VaultError> {
    for stamp in removed {
        let present = v
            .get(id)
            .is_some_and(|it| it.history.iter().any(|h| h.replaced_at == *stamp));
        if present {
            v.remove_history_entry(id, *stamp, now)?;
        }
    }
    Ok(())
}

/// Flattens `SyncedVault::edit(|v| core_call)` into one error message.
pub(super) fn edit_result<T>(
    r: Result<Result<T, VaultError>, vault_sync::SyncError>,
) -> Result<T, String> {
    match r {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(e)) => Err(e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

impl AppState {
    pub fn is_editing(&self) -> bool {
        !matches!(self.mode, Mode::View)
    }

    pub fn edit_buffer(&self) -> Option<&EditBuffer> {
        match &self.mode {
            Mode::View => None,
            Mode::Edit(b) | Mode::New(_, b) => Some(b),
        }
    }

    pub fn edit_buffer_mut(&mut self) -> Option<&mut EditBuffer> {
        match &mut self.mode {
            Mode::View => None,
            Mode::Edit(b) | Mode::New(_, b) => Some(b),
        }
    }

    /// Applies `f` to the edit buffer and re-renders. No-op outside edit mode.
    pub fn edit(&mut self, cx: &mut Context<Self>, f: impl FnOnce(&mut EditBuffer)) {
        if let Some(b) = self.edit_buffer_mut() {
            f(b);
            b.error = None;
            cx.notify();
        }
    }

    pub fn set_edit_title(&mut self, title: String, cx: &mut Context<Self>) {
        self.edit(cx, |b| b.item.title = title);
    }

    pub fn set_edit_name(&mut self, key: u64, name: String, cx: &mut Context<Self>) {
        self.edit(cx, |b| {
            if let Some(f) = b.field_mut(key) {
                f.name = name;
            }
        });
    }

    pub fn set_edit_value(&mut self, key: u64, value: SecretString, cx: &mut Context<Self>) {
        self.edit(cx, |b| {
            if let Some(f) = b.field_mut(key) {
                f.value = value;
            }
        });
    }

    /// The guard (§2.3): returns true if `nav` may proceed now. Leaving an edit with no
    /// changes just ends it; with changes, the inline "Discard changes?" prompt appears and
    /// the navigation waits for [`Self::discard_changes`].
    pub(super) fn guard(&mut self, nav: Navigation, cx: &mut Context<Self>) -> bool {
        match self.edit_buffer() {
            None => true,
            Some(b) if !b.has_changes() => {
                self.mode = Mode::View;
                true
            }
            Some(_) => {
                self.discard_prompt = Some(nav);
                cx.notify();
                false
            }
        }
    }

    /// "Discard" in the prompt: drop the edit and carry on where the user was going.
    pub fn discard_changes(&mut self, cx: &mut Context<Self>) {
        let Some(nav) = self.discard_prompt.take() else {
            return;
        };
        self.mode = Mode::View;
        match nav {
            Navigation::Select(id) => self.select(id, cx),
            Navigation::Offset(d) => self.select_offset(d, cx),
            Navigation::Filter(f) => self.set_filter(f, cx),
            Navigation::New(kind, title) => self.begin_new(kind, title, cx),
            Navigation::Edit => self.begin_edit(cx),
            Navigation::SwitchVault(intent) => self.switch_vault(intent, cx),
            Navigation::Restore(backup) => self.request_restore(backup, cx),
            Navigation::Security => {
                self.settings_tab = super::SECURITY_TAB;
                self.settings_open = true;
            }
        }
        cx.notify();
    }

    /// "Keep editing" in the prompt.
    pub fn keep_editing(&mut self, cx: &mut Context<Self>) {
        self.discard_prompt = None;
        cx.notify();
    }

    /// ⌘E / Edit button: edit the selected item.
    pub fn begin_edit(&mut self, cx: &mut Context<Self>) {
        if !self.main_active() {
            return;
        }
        if let Mode::New(..) = self.mode
            && !self.guard(Navigation::Edit, cx)
        {
            return;
        }
        if self.is_editing() {
            return;
        }
        let Some(item) = self.selected_item().cloned() else {
            return;
        };
        self.start(Mode::Edit(EditBuffer::new(item)), cx);
    }

    /// ⌘N, the New button and the empty-state buttons: show the Templates menu, pre-filling
    /// `title` into the new item ("Create '<query>'").
    pub fn open_template_picker(&mut self, title: String, cx: &mut Context<Self>) {
        if self.main_active() {
            self.template_picker = Some(title);
            cx.notify();
        }
    }

    pub fn close_template_picker(&mut self, cx: &mut Context<Self>) {
        if self.template_picker.take().is_some() {
            cx.notify();
        }
    }

    /// ⌘N picker result, or "Create '<query>'": a new item of `kind` in edit mode.
    pub fn begin_new(&mut self, template: Template, title: String, cx: &mut Context<Self>) {
        self.template_picker = None;
        if !self.main_active() || !self.guard(Navigation::New(template, title.clone()), cx) {
            return;
        }
        let now = text::now_millis();
        let item = template.new_item(title, self.device_id, now);
        self.start(Mode::New(template, EditBuffer::new(item)), cx);
    }

    fn start(&mut self, mode: Mode, cx: &mut Context<Self>) {
        self.mode = mode;
        self.edit_session = self.edit_session.wrapping_add(1);
        self.delete_confirm = None;
        self.discard_prompt = None;
        self.generator_target = None;
        cx.notify();
    }

    /// Esc / Cancel: drop the edit buffer without saving.
    pub fn cancel_edit(&mut self, cx: &mut Context<Self>) {
        if self.discard_prompt.take().is_some() {
            // Esc on the prompt means "keep editing".
            cx.notify();
            return;
        }
        if self.delete_confirm.take().is_some() {
            cx.notify();
            return;
        }
        if self.is_editing() {
            self.mode = Mode::View;
            self.generator_target = None;
            self.request_focus(FocusTarget::Detail, cx);
            cx.notify();
        }
    }

    /// ⌘S / Save: validate, write through core, mark dirty and schedule the autosave.
    pub fn save_edit(&mut self, cx: &mut Context<Self>) {
        if !self.main_active() {
            return;
        }
        let is_new = matches!(self.mode, Mode::New(..));
        let Some(buffer) = self.edit_buffer_mut() else {
            return;
        };
        let (keys, original) = (buffer.keys.clone(), buffer.original.clone());
        let removed = buffer.removed_history.clone();
        let mut item = match buffer.finished() {
            Ok(item) => item,
            Err(e) => {
                buffer.error = Some(e);
                cx.notify();
                return;
            }
        };
        let now = text::now_millis();
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        let result = if is_new {
            for f in &mut item.fields {
                f.modified_at = now;
            }
            vault.edit(|v| Ok(v.insert(item, now)))
        } else {
            vault.edit(|v| {
                // History removals first, so `apply_edit`'s field diff (and a changed
                // password's new history entry) runs on the trimmed history.
                remove_history(v, item.id, &removed, now)?;
                apply_edit(v, item, &keys, &original, now)
            })
        };
        let id = match edit_result(result) {
            Ok(id) => id,
            Err(e) => return self.edit_failed(e, cx),
        };
        self.mode = Mode::View;
        self.discard_prompt = None;
        self.generator_target = None;
        self.vault_changed();
        if is_new {
            self.reveal_new(id);
        }
        self.schedule_autosave(cx);
        self.request_focus(FocusTarget::Detail, cx);
        cx.notify();
    }

    fn edit_failed(&mut self, message: String, cx: &mut Context<Self>) {
        self.edit(cx, |b| {
            b.error = Some(format!("Could not save: {message}").into())
        });
    }

    /// Selects a just-created item, widening the filter or clearing the search if they
    /// would hide it.
    fn reveal_new(&mut self, id: Uuid) {
        if !self.listing.items.contains(&id) && self.filter != Filter::All {
            self.filter = Filter::All;
            self.refresh();
        }
        if !self.listing.items.contains(&id) && !self.query.is_empty() {
            self.query.clear();
            self.clear_search = true;
            self.refresh();
        }
        if self.listing.items.contains(&id) {
            self.set_selection(Some(id));
        }
    }

    /// ⌘⌫ / Item ▸ Delete: show the inline confirm for the selected item. Read mode only:
    /// the confirm lives in the read-mode header, and an edit must be saved or cancelled first.
    pub fn request_delete(&mut self, cx: &mut Context<Self>) {
        if !self.main_active() || self.is_editing() {
            return;
        }
        if let Some(id) = self.selected_item().map(|i| i.id) {
            self.delete_confirm = Some(id);
            cx.notify();
        }
    }

    pub fn cancel_delete(&mut self, cx: &mut Context<Self>) {
        self.delete_confirm = None;
        cx.notify();
    }

    /// "Delete" in the confirm: tombstone the item, then select the next one.
    pub fn confirm_delete(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.delete_confirm.take() else {
            return;
        };
        if !self.main_active() || self.selection != Some(id) {
            cx.notify();
            return;
        }
        let at = self.listing.items.iter().position(|i| *i == id);
        let now = text::now_millis();
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        if let Err(e) = edit_result(vault.edit(|v| v.delete(id, now))) {
            return self.show_toast(format!("Could not delete: {e}"), cx);
        }
        self.mode = Mode::View;
        self.vault_changed();
        // The item that slid into the deleted one's place, else the one before it.
        let items = &self.listing.items;
        let next = at.and_then(|i| items.get(i).or_else(|| items.last()).copied());
        self.set_selection(next);
        self.schedule_autosave(cx);
        cx.notify();
    }
}

#[cfg(test)]
#[path = "edit_tests.rs"]
mod tests;
