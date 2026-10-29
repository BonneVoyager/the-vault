//! Edit mode, new items, delete and the unsaved-changes guard (specs/05-ui.md §2.3, §3).
//!
//! The `EditBuffer` lives in `AppState::mode` and is the single source of truth while
//! editing: the editor view writes every keystroke into it as a `SecretString`, and the
//! global ⌘S handler saves it without needing the view. Field values never leave
//! `SecretString` here.

use gpui::{Context, SharedString};
use vault_core::{
    ExposeSecret, Field, FieldKind, Item, ItemKind, SecretString, Totp, UnlockedVault, Uuid,
    VaultError,
};

use super::{AppState, ChooseIntent, Filter, FocusTarget, Mode};
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
        }
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
        let base = kind_name(kind);
        let mut name = base.to_owned();
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
        normalize_tag(&self.tag_draft).is_some_and(|d| {
            let d = d.to_lowercase();
            !self.item.tags.iter().any(|t| t.to_lowercase() == d)
        })
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
    if tags.iter().any(|t| t.to_lowercase() == tag.to_lowercase()) {
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

/// User-facing name of a field kind (badge, "Add field" menu, default field name).
pub fn kind_name(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Text => "text",
        FieldKind::Password => "password",
        FieldKind::Totp => "one-time code",
        FieldKind::Url => "url",
        FieldKind::Notes => "notes",
        FieldKind::Email => "email",
        FieldKind::Date => "date",
        FieldKind::MonthYear => "month/year",
        FieldKind::Number => "number",
        FieldKind::Other => FieldKind::Other.as_str(),
    }
}

/// Template fields for a new item of `kind`.
pub fn template(kind: ItemKind) -> &'static [(&'static str, FieldKind)] {
    match kind {
        ItemKind::Login => &[
            ("username", FieldKind::Text),
            ("password", FieldKind::Password),
            ("url", FieldKind::Url),
            ("notes", FieldKind::Notes),
        ],
        ItemKind::Note => &[("notes", FieldKind::Notes)],
        ItemKind::Card => &[
            ("number", FieldKind::Text),
            ("expiry", FieldKind::MonthYear),
            ("cvv", FieldKind::Password),
            ("name", FieldKind::Text),
        ],
        ItemKind::Identity => &[
            ("first name", FieldKind::Text),
            ("last name", FieldKind::Text),
            ("email", FieldKind::Email),
            ("phone", FieldKind::Number),
            ("address", FieldKind::Notes),
        ],
        // Never offered for new items; title only.
        ItemKind::Other => &[],
    }
}

/// Where the user was going when the unsaved-changes guard stopped them.
#[derive(Debug, Clone, PartialEq)]
pub enum Navigation {
    Select(Uuid),
    Offset(isize),
    Filter(Filter),
    New(ItemKind, String),
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

    /// ⌘N, the New button and the empty-state buttons: show the kind picker, pre-filling
    /// `title` into the new item ("Create '<query>'").
    pub fn open_kind_picker(&mut self, title: String, cx: &mut Context<Self>) {
        if self.main_active() {
            self.kind_picker = Some(title);
            cx.notify();
        }
    }

    pub fn close_kind_picker(&mut self, cx: &mut Context<Self>) {
        if self.kind_picker.take().is_some() {
            cx.notify();
        }
    }

    /// ⌘N picker result, or "Create '<query>'": a new item of `kind` in edit mode.
    pub fn begin_new(&mut self, kind: ItemKind, title: String, cx: &mut Context<Self>) {
        self.kind_picker = None;
        if !self.main_active() || !self.guard(Navigation::New(kind, title.clone()), cx) {
            return;
        }
        let now = text::now_millis();
        let mut item = Item::new(kind, title, self.device_id, now);
        item.fields = template(kind)
            .iter()
            .map(|(name, fk)| Field::new(*name, *fk, SecretString::new(String::new()), now))
            .collect();
        self.start(Mode::New(kind, EditBuffer::new(item)), cx);
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
            vault.edit(|v| apply_edit(v, item, &keys, &original, now))
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
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use gpui::{AppContext as _, Entity, TestAppContext};
    use vault_core::KdfParams;
    use vault_sync::{NoopHooks, SyncedVault};

    use super::*;

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.into())
    }

    /// Unlocked state over a vault with a login ("GitHub") and a note ("Alarm").
    fn setup(dir: &Path, cx: &mut TestAppContext) -> (Entity<AppState>, Uuid, Uuid) {
        let mut vault = SyncedVault::create(
            &dir.join("t.vault"),
            &secret("pw"),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let (gh, note) = vault
            .edit(|v| {
                let mut gh = Item::new(ItemKind::Login, "GitHub", device, 10);
                gh.fields = vec![
                    Field::new("username", FieldKind::Text, secret("chris"), 10),
                    Field::new("password", FieldKind::Password, secret("old"), 10),
                ];
                let note = Item::new(ItemKind::Note, "Alarm", device, 10);
                (v.insert(gh, 10), v.insert(note, 10))
            })
            .unwrap();
        vault.save().unwrap();
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        state.update(cx, |s, _| {
            s.install(vault, false);
            s.unlocked();
        });
        (state, gh, note)
    }

    fn stored(s: &AppState, id: Uuid) -> Item {
        s.unlocked_vault().unwrap().get(id).unwrap().clone()
    }

    #[gpui::test]
    fn save_changes_one_field_and_bumps_only_its_stamp(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            let before = stored(s, gh);
            s.begin_edit(cx);
            let key = s.edit_buffer().unwrap().keys[0];
            s.set_edit_value(key, secret("christopher"), cx);
            assert!(s.edit_buffer().unwrap().has_changes());
            s.save_edit(cx);
            assert!(!s.is_editing());
            assert!(s.vault.as_ref().unwrap().is_dirty());

            let after = stored(s, gh);
            assert_eq!(after.fields[0].value.expose_secret(), "christopher");
            assert!(after.fields[0].modified_at > before.fields[0].modified_at);
            assert_eq!(after.fields[1].modified_at, before.fields[1].modified_at);
            assert!(after.history.is_empty(), "username is not a password");
        });
    }

    #[gpui::test]
    fn password_change_keeps_history_and_order_changes_save(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.begin_edit(cx);
            let b = s.edit_buffer().unwrap();
            let pw = b.keys[1];
            s.set_edit_value(pw, secret("new"), cx);
            s.edit(cx, |b| b.move_field(pw, 0));
            s.save_edit(cx);
            let after = stored(s, gh);
            assert_eq!(after.fields[0].name, "password");
            assert_eq!(after.fields[0].value.expose_secret(), "new");
            assert_eq!(after.history.len(), 1);
            assert_eq!(after.history[0].value.expose_secret(), "old");
        });
    }

    #[gpui::test]
    fn changes_merged_in_while_editing_survive_save(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.begin_edit(cx);
            // A phase-3 merge lands behind the buffer's back: new password, new field.
            let vault = s.vault.as_mut().unwrap();
            vault
                .edit(|v| {
                    v.set_field(gh, "password", secret("remote"), 50)?;
                    v.update(gh, 50, |it| {
                        it.fields
                            .push(Field::new("pin", FieldKind::Text, secret("1234"), 50))
                    })
                })
                .unwrap()
                .unwrap();
            let merged = stored(s, gh);
            // The user only edits the username.
            let user = s.edit_buffer().unwrap().keys[0];
            s.set_edit_value(user, secret("christopher"), cx);
            s.save_edit(cx);

            let after = stored(s, gh);
            let pw = after.field("password").unwrap();
            assert_eq!(pw.value.expose_secret(), "remote", "remote change survives");
            assert_eq!(
                pw.modified_at,
                merged.field("password").unwrap().modified_at
            );
            assert_eq!(
                after.history.len(),
                merged.history.len(),
                "no bogus history"
            );
            assert_eq!(after.field("pin").unwrap().value.expose_secret(), "1234");
            assert_eq!(
                after.field("username").unwrap().value.expose_secret(),
                "christopher"
            );
        });
    }

    #[gpui::test]
    fn rename_and_change_password_records_history(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.begin_edit(cx);
            let pw = s.edit_buffer().unwrap().keys[1];
            s.set_edit_name(pw, "master".into(), cx);
            s.set_edit_value(pw, secret("new"), cx);
            s.save_edit(cx);
            let after = stored(s, gh);
            assert!(after.field("password").is_none());
            assert_eq!(after.field("master").unwrap().value.expose_secret(), "new");
            assert_eq!(after.history.len(), 1);
            assert_eq!(after.history[0].value.expose_secret(), "old");
        });
    }

    #[gpui::test]
    fn switch_vault_and_new_mode_clicks_are_guarded(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.begin_edit(cx);
            s.set_edit_title("Changed".into(), cx);
            s.switch_vault(ChooseIntent::Home, cx);
            assert_eq!(
                s.screen,
                crate::state::Screen::Main,
                "⌘O waits for the prompt"
            );
            assert_eq!(
                s.discard_prompt,
                Some(Navigation::SwitchVault(ChooseIntent::Home))
            );
            s.discard_changes(cx);
            assert_eq!(s.screen, crate::state::Screen::Choose);
        });

        let dir = tempfile::tempdir().unwrap();
        let (state, _, note2) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(note2, cx);
            s.begin_new(ItemKind::Login, "Draft".into(), cx);
            // An untouched draft is no change: the click would just end it. Type first.
            s.set_edit_title("Draft 2".into(), cx);
            // Clicking the still-highlighted previous row is navigation in New mode.
            s.select(note2, cx);
            assert_eq!(s.discard_prompt, Some(Navigation::Select(note2)));
            s.discard_changes(cx);
            assert!(!s.is_editing());
        });
    }

    #[gpui::test]
    fn validation_rejects_empty_title_and_duplicate_names(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.begin_edit(cx);
            s.set_edit_title("   ".into(), cx);
            s.save_edit(cx);
            assert_eq!(
                s.edit_buffer().unwrap().error.as_deref(),
                Some("Title required")
            );
            assert_eq!(stored(s, gh).title, "GitHub");

            s.set_edit_title("GitHub".into(), cx);
            let key = s.edit_buffer().unwrap().keys[1];
            s.set_edit_name(key, "username".into(), cx);
            s.save_edit(cx);
            assert!(s.edit_buffer().unwrap().error.is_some());

            // Removing every field is allowed.
            let keys = s.edit_buffer().unwrap().keys.clone();
            for k in keys {
                s.edit(cx, |b| b.remove_field(k));
            }
            s.save_edit(cx);
            assert!(!s.is_editing());
            assert!(stored(s, gh).fields.is_empty());
        });
    }

    #[gpui::test]
    fn new_item_inserts_template_and_selects_it(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            // A filter that would hide the new item is widened on save.
            s.set_filter(Filter::Kind(ItemKind::Note), cx);
            s.begin_new(ItemKind::Card, "Visa".into(), cx);
            let b = s.edit_buffer().unwrap();
            let names: Vec<_> = b.item.fields.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(names, ["number", "expiry", "cvv", "name"]);
            assert_eq!(b.item.fields[1].kind, FieldKind::MonthYear);
            s.save_edit(cx);
            assert!(!s.is_editing());
            let item = s.selected_item().expect("new item selected");
            assert_eq!(item.title, "Visa");
            assert_eq!(item.kind, ItemKind::Card);
            assert_eq!(item.fields.len(), 4);
            assert_eq!(s.counts.all, 3);
            assert_eq!(s.filter, Filter::All);
        });
    }

    #[gpui::test]
    fn cancel_discards_and_guard_prompts(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, note) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.begin_edit(cx);
            s.set_edit_title("Changed".into(), cx);
            s.cancel_edit(cx);
            assert!(!s.is_editing());
            assert_eq!(stored(s, gh).title, "GitHub");
            assert!(!s.vault.as_ref().unwrap().is_dirty());

            // Unchanged edit: navigation just ends it.
            s.begin_edit(cx);
            s.select(note, cx);
            assert!(!s.is_editing());
            assert_eq!(s.selection, Some(note));

            // Changed edit: navigation waits behind the prompt.
            s.select(gh, cx);
            s.begin_edit(cx);
            s.set_edit_title("Changed".into(), cx);
            s.select(note, cx);
            assert_eq!(s.selection, Some(gh));
            assert_eq!(s.discard_prompt, Some(Navigation::Select(note)));
            s.keep_editing(cx);
            assert!(s.is_editing());
            s.set_filter(Filter::Favorites, cx);
            assert_eq!(s.filter, Filter::All);
            s.discard_changes(cx);
            assert!(!s.is_editing());
            assert_eq!(s.filter, Filter::Favorites);

            // Cancel mid-new, and lock mid-edit, are both clean.
            s.set_filter(Filter::All, cx);
            s.begin_new(ItemKind::Login, String::new(), cx);
            s.cancel_edit(cx);
            assert_eq!(s.counts.all, 2);
            s.select(gh, cx);
            s.begin_edit(cx);
            s.set_edit_title("Changed".into(), cx);
            s.lock(cx);
            assert!(!s.is_editing(), "lock discards the edit");
            assert!(s.discard_prompt.is_none());
        });
    }

    #[gpui::test]
    fn delete_tombstones_and_moves_selection(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, note) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            // A–Z: Alarm, GitHub. Delete Alarm: GitHub slides into its place.
            s.select(note, cx);
            s.request_delete(cx);
            assert_eq!(s.delete_confirm, Some(note));
            s.cancel_delete(cx);
            assert_eq!(s.counts.all, 2);
            s.request_delete(cx);
            s.confirm_delete(cx);
            assert!(s.unlocked_vault().unwrap().get(note).unwrap().is_deleted());
            assert_eq!(s.selection, Some(gh));
            assert!(s.vault.as_ref().unwrap().is_dirty());
            // Deleting the last item leaves an empty, selection-less vault.
            s.request_delete(cx);
            s.confirm_delete(cx);
            assert_eq!(s.counts.all, 0);
            assert_eq!(s.selection, None);
            s.request_delete(cx);
            assert!(s.delete_confirm.is_none());
        });
    }

    #[gpui::test]
    fn tags_are_added_deduped_removed_and_saved(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.begin_edit(cx);
            s.edit(cx, |b| {
                assert!(b.add_tag(" work "));
                assert!(b.add_tag("#Infra"));
                assert!(!b.add_tag("WORK"), "case-insensitive duplicate");
                assert!(!b.add_tag("##infra"), "duplicate after # strip");
                assert!(!b.add_tag("   "), "blank");
                assert!(!b.add_tag("#"), "only a hash");
                // Comma commits; the text after the last comma stays as the draft.
                assert_eq!(b.type_tags("a, ,b,c").as_deref(), Some("c"));
                assert_eq!(b.tag_draft, "c");
                assert_eq!(b.type_tags("cd"), None);
                assert_eq!(b.tag_draft, "cd");
                b.remove_tag(2); // "a"
                b.remove_tag(99); // out of range: no-op
            });
            assert!(s.edit_buffer().unwrap().has_changes());
            // Save commits the pending draft too.
            s.save_edit(cx);
            assert!(!s.is_editing());
            assert_eq!(stored(s, gh).tags, ["work", "Infra", "b", "cd"]);
            let names: Vec<_> = s.counts.tags.iter().map(|t| t.0.as_str()).collect();
            assert_eq!(names, ["b", "cd", "Infra", "work"], "sidebar counts follow");

            // A second edit that only removes a tag writes just that.
            s.begin_edit(cx);
            s.edit(cx, |b| b.remove_tag(0));
            s.save_edit(cx);
            assert_eq!(stored(s, gh).tags, ["Infra", "b", "cd"]);
        });
    }

    #[gpui::test]
    fn tags_on_a_new_item_and_untouched_tags_keep_remote_changes(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.begin_new(ItemKind::Note, "Tagged".into(), cx);
            s.edit(cx, |b| {
                b.add_tag("home");
            });
            s.save_edit(cx);
            assert_eq!(s.selected_item().unwrap().tags, ["home"]);

            // Tags merged in while editing survive an edit that does not touch tags.
            s.select(gh, cx);
            s.begin_edit(cx);
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| v.update(gh, 50, |it| it.tags = vec!["remote".into()]))
                .unwrap()
                .unwrap();
            s.set_edit_title("GitHub 2".into(), cx);
            s.save_edit(cx);
            assert_eq!(stored(s, gh).tags, ["remote"]);
        });
    }

    fn totp_buffer(value: &str) -> (EditBuffer, u64) {
        let mut item = Item::new(ItemKind::Login, "My Bank: ü", Uuid::new_v4(), 1);
        item.fields = vec![Field::new("one-time code", FieldKind::Totp, secret(""), 1)];
        let mut b = EditBuffer::new(item);
        let key = b.keys[0];
        // Typed by the user, so the save normalises it.
        b.field_mut(key).unwrap().value = secret(value);
        (b, key)
    }

    #[test]
    fn totp_values_are_trimmed_and_bare_secrets_become_uris() {
        const URI: &str =
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let (b, key) = totp_buffer(&format!("  {URI}\n"));
        assert_eq!(b.totp_hint(key), Some((true, TOTP_VALID)));
        let saved = b.finished().unwrap();
        assert_eq!(saved.fields[0].value.expose_secret(), URI);

        let (b, key) = totp_buffer(" jbsw y3dp ehpk 3pxp ");
        assert_eq!(b.totp_hint(key), Some((true, TOTP_VALID_SECRET)));
        let saved = b.finished().unwrap();
        let uri = saved.fields[0].value.expose_secret();
        assert!(
            uri.starts_with("otpauth://totp/My%20Bank%3A%20%C3%BC?secret=JBSWY3DPEHPK3PXP"),
            "label is the title"
        );
        let a = Totp::parse_uri(uri).unwrap();
        let b2 = Totp::from_secret_base32("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(a.code(59), b2.code(59), "same secret");

        let (b, key) = totp_buffer("otpauth://totp/broken");
        assert_eq!(b.totp_hint(key), Some((false, TOTP_INVALID)));
        assert_eq!(
            b.finished().unwrap().fields[0].value.expose_secret(),
            "otpauth://totp/broken",
            "kept as typed; the editor flags it"
        );
        let (b, key) = totp_buffer("not a secret!");
        assert_eq!(b.totp_hint(key), Some((false, TOTP_INVALID)));
        let (b, key) = totp_buffer("   ");
        assert_eq!(b.totp_hint(key), None);
        assert_eq!(b.finished().unwrap().fields[0].value.expose_secret(), "");
    }

    #[gpui::test]
    fn untouched_raw_totp_is_not_rewritten_and_remote_update_survives(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, _) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            // As an import stores it: a bare, untrimmed secret.
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| {
                    v.update(gh, 20, |it| {
                        it.fields.push(Field::new(
                            "totp",
                            FieldKind::Totp,
                            secret(" jbswy3dpehpk3pxp "),
                            20,
                        ))
                    })
                })
                .unwrap()
                .unwrap();
            s.select(gh, cx);
            s.begin_edit(cx);
            // Another device updates the TOTP while the user edits only the title.
            let remote = "otpauth://totp/GitHub?secret=GEZDGNBVGY3TQOJQ";
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| v.set_field(gh, "totp", secret(remote), 60))
                .unwrap()
                .unwrap();
            let merged = stored(s, gh);
            s.set_edit_title("GitHub 2".into(), cx);
            s.save_edit(cx);
            assert!(!s.is_editing());
            let after = stored(s, gh);
            let totp = after.field("totp").unwrap();
            assert_eq!(totp.value.expose_secret(), remote, "remote update survives");
            assert_eq!(totp.modified_at, merged.field("totp").unwrap().modified_at);
            assert_eq!(after.title, "GitHub 2");

            // Untouched raw value with no remote change: stays byte-identical.
            s.vault
                .as_mut()
                .unwrap()
                .edit(|v| v.set_field(gh, "totp", secret(" jbswy3dpehpk3pxp "), 70))
                .unwrap()
                .unwrap();
            let before = stored(s, gh);
            s.begin_edit(cx);
            s.set_edit_title("GitHub 3".into(), cx);
            s.save_edit(cx);
            let after = stored(s, gh);
            let (a, b) = (after.field("totp").unwrap(), before.field("totp").unwrap());
            assert_eq!(a.value.expose_secret(), " jbswy3dpehpk3pxp ");
            assert_eq!(a.modified_at, b.modified_at, "stamp not bumped");

            // Touched: now it is normalised.
            s.begin_edit(cx);
            let key = s.edit_buffer().unwrap().keys[2];
            s.set_edit_value(key, secret(" jbswy3dpehpk3pxp\n"), cx);
            s.save_edit(cx);
            let v = stored(s, gh)
                .field("totp")
                .unwrap()
                .value
                .expose_secret()
                .to_owned();
            assert!(v.starts_with("otpauth://totp/GitHub%203?secret=JBSWY3DPEHPK3PXP"));
        });
    }

    #[gpui::test]
    fn duplicate_draft_is_no_change_and_cancel_discards_the_draft(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let (state, gh, note) = setup(dir.path(), cx);
        state.update(cx, |s, cx| {
            s.select(gh, cx);
            s.begin_edit(cx);
            s.edit(cx, |b| {
                b.add_tag("work");
            });
            s.save_edit(cx);

            s.begin_edit(cx);
            s.edit(cx, |b| {
                b.type_tags(" #WORK ");
            });
            assert!(!s.edit_buffer().unwrap().has_changes(), "duplicate draft");
            s.edit(cx, |b| {
                b.type_tags("   ");
            });
            assert!(!s.edit_buffer().unwrap().has_changes(), "blank draft");
            // So navigation just ends the edit, no prompt.
            s.select(note, cx);
            assert!(s.discard_prompt.is_none());
            assert!(!s.is_editing());

            // A real draft is a change; Cancel drops it.
            s.select(gh, cx);
            s.begin_edit(cx);
            s.edit(cx, |b| {
                b.type_tags("home");
            });
            assert!(s.edit_buffer().unwrap().has_changes());
            s.cancel_edit(cx);
            assert!(!s.is_editing());
            assert_eq!(stored(s, gh).tags, ["work"]);
            s.begin_edit(cx);
            assert_eq!(s.edit_buffer().unwrap().tag_draft, "", "fresh buffer");
            s.save_edit(cx);
            assert_eq!(stored(s, gh).tags, ["work"]);
        });
    }
}
