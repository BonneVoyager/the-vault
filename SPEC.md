# 05 — `vault-app`: UI

> Reference draft. The maintained UI specification is [specs/05-ui.md](specs/05-ui.md).

Framework: `gpui` + `gpui-component`, versions pinned with `=`. Treat gpui as pre-1.0: wrap any API we touch in more than two places behind our own thin helper so an upstream rename is a one-file fix.

Reference look: 1Password 8 for macOS. Three columns, 13 pt system font, generous whitespace, subtle borders rather than heavy chrome, native-feeling vibrancy on the sidebar in light mode.

## 1. Window and layout

Single main window, 1100×720 default, min 820×520, state persisted (size, position, column widths) in `~/Library/Application Support/<bundle id>/window.json`. Title bar: hidden-title transparent style with traffic lights inset; the sidebar extends under it.

```
┌─────────────┬──────────────────────┬────────────────────────────────┐
│ Sidebar     │ Item list            │ Detail                         │
│ 220 px      │ 300 px               │ fill                           │
│ (180–320)   │ (240–420)            │                                │
│             │ ┌──────────────────┐ │  Title                         │
│ All Items   │ │ 🔍 Search   ⌘F   │ │  ─────────────────             │
│ Favorites   │ └──────────────────┘ │  username   chris@…     [copy] │
│ ──────      │ ▸ GitHub             │  password   ••••••••  [👁][copy]│
│ Logins      │   chris@aurora.dev   │  totp       482 193  ◔   [copy]│
│ Notes       │ ▸ Hetzner            │  website    github.com  [open] │
│ Cards       │ ...                  │                                 │
│ Identities  │                      │  notes                          │
│ ──────      │                      │                                 │
│ Tags ▾      │                      │  ─────────────────             │
│   #infra    │                      │  modified 2h ago · GitHub Mac   │
│ ──────      │                      │                                 │
│ ⚙︎ Settings  │  [+ New]             │                         [Edit] │
└─────────────┴──────────────────────┴────────────────────────────────┘
```

Columns are resizable via gpui-component's resizable panel; sidebar collapsible with `⌘⌥S`.

## 2. Screens / states

### 2.1 Launch → choose vault
First run, or no vault remembered: card with "Create new vault" / "Open existing vault…" / recent vaults list. Create flow: name, location (folder picker; shows a hint badge when the chosen folder is inside iCloud Drive or Dropbox), master password + confirm with strength meter, "Calibrating encryption for this Mac…" spinner (KDF calibrate), done.

### 2.2 Unlock
Centered card: vault name, lock icon, password field (autofocus), "Unlock" button, Touch ID button if enrolled (triggers automatically on appear if enrolled and policy allows). Wrong password: field shakes, inline error, no lockout counter in v1. `⌘O` switches vault.

### 2.3 Main (locked → unlocked transition is a 150 ms crossfade)

**Sidebar**: sections per the sketch. Counts shown right-aligned in a muted color. Tags section collapsible, sorted alphabetically. Settings opens a sheet (not a separate window).

**Item list**: search field pinned at top; rows are 56 px: 32 px icon (letter avatar from title, deterministic color from id hash; bundled favicon set in phase 5), title (semibold), subtitle (username / card last-4 / first line of note), favorite star right-aligned. Grouped by first letter when sorted A–Z; sort menu: A–Z, recently modified, recently created. Empty state illustration + "Create your first item" when the vault is empty; "No results" with "Create '<query>'" when search is empty. Virtualized list.

**Detail**: read mode by default. Fields rendered per `FieldKind`:
- `text`, `email`, `url`: value + copy; `url` also gets "open in browser"
- `password`: dots, reveal toggle (`⌘⇧R`), copy (`⌘⇧C`), strength meter under it in edit mode, history disclosure (last 10 values with timestamps, each copyable)
- `totp`: 6-digit code grouped as `482 193`, circular countdown ring, copy; auto-refresh every second; code turns amber under 5 s
- `notes`: multiline, markdown **not** rendered (plain text)
- `card`: number shown as `•••• •••• •••• 4242`, reveal toggle
- `date`, `month_year`, `number`: plain

Copy shows a transient "Copied — clears in 30 s" pill at the bottom of the detail column.

**Edit mode** (`⌘E` or Edit button): title becomes editable, each field gets name/value inputs, "Add field" menu with kinds, field drag-to-reorder, "Generate" button inside password fields opens the generator popover, "Scan QR from screen" in TOTP fields is phase 5. Save `⌘S` / Cancel `Esc`. Unsaved-changes guard when navigating away: inline "Discard changes?" confirm, not a modal.

**New item** (`⌘N`): kind picker popover, then detail opens in edit mode with the kind's template fields.

### 2.4 Password generator (popover, also `⌘G` globally)
Tabs: Password / Passphrase. Live preview (monospace, symbols tinted, digits tinted), length slider 8–64, class toggles, exclude-ambiguous, regenerate button, copy, "Use" (when opened from a field).

### 2.5 Settings sheet
Tabs:
- **General**: auto-lock after (1/5/15/60 min/never), lock on sleep/screen lock (on), clear clipboard after (15/30/60/90 s), launch at login (off, phase 5)
- **Security**: Touch ID toggle, change master password, re-calibrate KDF ("Encryption strength: ~0.6 s on this Mac"), rotate vault key (advanced, collapsed)
- **Sync & Backup**: vault path with "Move…" and "Reveal in Finder", status line (last synced, cloud provider detected), backups list with open/restore, "Back up now", retention multiplier
- **Import / Export**: CSV, 1PUX, KDBX import; CSV export behind a red confirm
- **About**: version, licenses

## 3. State model

One `AppState` entity (gpui `Entity<AppState>`) owning:

```rust
pub struct AppState {
    pub vault: Option<SyncedVault>,          // None = no vault chosen
    pub locked: bool,
    pub selection: Option<Uuid>,
    pub filter: Filter,                       // All | Favorites | Kind(ItemKind) | Tag(String)
    pub query: String,
    pub sort: Sort,
    pub mode: Mode,                           // View | Edit(EditBuffer) | New(ItemKind, EditBuffer)
    pub toast: Option<Toast>,
    pub sync_status: SyncStatus,
    pub settings: Settings,
    pub last_activity: Instant,
}
```

Views subscribe to `AppState` and re-render on `notify()`. Derived data (`filtered_items: Vec<Uuid>`) is recomputed on `query`/`filter`/`sort`/vault change and cached in state, not recomputed per frame.

`EditBuffer` is a plain clone of the `Item` being edited; Save calls `vault.edit(|v| v.update(id, now, |it| *it = buffer))`. Core recomputes field timestamps by diff (see 02 §`update`).

Sync events arrive on a `crossbeam_channel` receiver polled from a gpui background task; each event mutates `AppState` on the main thread and `notify()`s. `Merged` while editing: keep the edit buffer, show a toast "Vault updated from another device"; if the merged item is the one being edited and a field the user has touched changed remotely, mark that field with a small badge "changed remotely — your edit will win on save".

Auto-lock: a 1 s timer checks `vault_macos::seconds_since_user_input()` and `last_activity`; on threshold → `lock()`. Lock = save if dirty, `vault.lock()`, clear selection and edit buffer, clear clipboard if ours, switch to Unlock screen.

## 4. Actions and keymap

Use gpui's action system; every action is also in the menu bar so it's discoverable.

| Action | Key | Where |
|---|---|---|
| Search | ⌘F | global |
| New item | ⌘N | global |
| Edit / Save | ⌘E / ⌘S | detail |
| Cancel edit | Esc | detail |
| Copy username | ⌘C (when row focused) / ⌘⇧U | list, detail |
| Copy password | ⌘⇧C | list, detail |
| Copy TOTP | ⌘⇧T | list, detail |
| Reveal password | ⌘⇧R | detail |
| Open URL | ⌘⇧O | detail |
| Favorite | ⌘D | list, detail |
| Delete item | ⌘⌫ (confirm) | list, detail |
| Generator | ⌘G | global |
| Lock | ⌘L | global |
| Settings | ⌘, | global |
| Toggle sidebar | ⌘⌥S | global |
| Next/prev item | ↓ / ↑ | list |
| Focus list / detail | ⌘1 / ⌘2 | global |

Menu bar: standard App / File (New Vault, Open Vault, Lock, Import, Export) / Edit / Item (the item actions) / View (sort, sidebar) / Window / Help.

## 5. Theme

Use gpui-component's theme system. Define our tokens on top:

```
accent         light: #3B6CF0   dark: #5B8CFF
bg             light: #FFFFFF   dark: #1C1C1E
bg-sidebar     light: vibrancy  dark: #232326
bg-elevated    light: #F7F7F8   dark: #2A2A2D
border         light: #E5E5EA   dark: #38383B
text           light: #1D1D1F   dark: #F2F2F7
text-muted     light: #6E6E73   dark: #98989D
danger         #E5484D
warning        #F5A524
success        #30A46C
mono-font      "SF Mono", "Menlo", monospace   (passwords, TOTP, generator)
radius         8 px panels, 6 px inputs/buttons
```

Follow system appearance by default; override in Settings (phase 5). Motion: 120–180 ms ease-out for panel transitions, none for list scrolling. Respect "Reduce motion".

## 6. Accessibility and input

- Every interactive element reachable by Tab; focus ring visible.
- Dynamic type: respect the system text size step (phase 5).
- VoiceOver labels on icon-only buttons.
- No information conveyed by color alone (TOTP expiry also pulses the ring; strength meter has a label).

## 7. Phase-2 definition of done

Everything in §2.2–2.4 working against a real `.vault` file via `vault-sync` (watcher may be a no-op stub in phase 2), all actions in §4 bound, light and dark, no panics on empty vault, resizing, or rapid lock/unlock. Settings sheet may be a stub with the General tab only.

## 8. Out of scope for v1 UI

Multiple windows, multiple simultaneously-open vaults, drag-and-drop between vaults, menu bar extra, Spotlight-style quick access window, browser integration, favicon fetching over the network (bundled icon pack only), markdown in notes.
