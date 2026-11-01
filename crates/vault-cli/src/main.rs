//! `vault`: thin dev/debug CLI over `vault-core`. Phase 1 deliverable.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use vault_core::{
    CsvMapping, ExposeSecret, FORMAT_VERSION, Field, FieldKind, Item, ItemIcon, KdfParams,
    PassphraseSpec, PasswordSpec, Query, SecretString, Totp, UnlockedVault, Uuid, VaultError,
    attachment::MAX_ATTACHMENT_SIZE, export_csv, import_csv, passphrase, password, search,
    strength_bits,
};
use vault_sync::{AttachmentState, NoopHooks, SyncError, SyncedVault};

mod edit;

/// Write to stdout/stderr like `println!`/`eprintln!`, but a closed pipe (`| grep -q`, `| head`)
/// ends the program quietly with status 0 instead of panicking. Any other write error still
/// panics, as the std macros do.
fn write_or_exit(res: std::io::Result<()>, what: &str) {
    match res {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        Err(e) => panic!("failed printing to {what}: {e}"),
    }
}

macro_rules! println {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        write_or_exit(writeln!(std::io::stdout(), $($arg)*), "stdout")
    }};
}

macro_rules! eprintln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        write_or_exit(writeln!(std::io::stderr(), $($arg)*), "stderr")
    }};
}

#[derive(Parser)]
#[command(
    name = "vault",
    about = "Dev/debug CLI for the vault password manager",
    after_help = "Environment:\n  VAULT_FILE        vault package path (same as --vault)\n  VAULT_DEVICE_ID   use this UUID as the device id instead of the stored one"
)]
struct Cli {
    /// Path to the vault package directory (`<name>.vault`).
    #[arg(long, global = true, env = "VAULT_FILE")]
    vault: Option<PathBuf>,
    /// Read the master password from this environment variable instead of prompting.
    #[arg(long, global = true, value_name = "VAR")]
    password_env: Option<String>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault.
    Init {
        /// Use fast test KDF parameters instead of calibrating.
        #[arg(long)]
        kdf_test_params: bool,
        /// Accept a master password under 50 bits of strength (for scripts and tests).
        #[arg(long)]
        allow_weak: bool,
    },
    /// Add an item.
    Add(AddArgs),
    /// Show an item.
    Get {
        id_or_title: String,
        #[arg(long)]
        reveal: bool,
        /// Show each field's id in a trailing column.
        #[arg(long)]
        ids: bool,
    },
    /// Edit an item. Values given on the command line are visible in process listings (ps,
    /// shell history); use --set-env for secrets.
    Edit(EditArgs),
    /// Absorb queued conflict copies, merge pending changes from disk and save if needed.
    Sync,
    /// Upgrade the vault file to the current format version (drops non-password slots).
    Upgrade {
        /// Do not warn when the master password is under 50 bits of strength.
        #[arg(long)]
        allow_weak: bool,
    },
    /// List items.
    List {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        favorites: bool,
        query: Option<String>,
    },
    /// Delete an item (tombstone).
    Rm { id_or_title: String },
    /// Print the current TOTP code.
    Totp { id_or_title: String },
    /// Generate a password or passphrase.
    Gen(GenArgs),
    /// Export all items as plaintext CSV.
    Export {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        yes: bool,
        /// Overwrite --out if it already exists.
        #[arg(long)]
        force: bool,
    },
    /// Manage item attachments.
    Attach {
        #[command(subcommand)]
        cmd: AttachCmd,
    },
    /// Import items.
    Import {
        #[arg(long)]
        format: String,
        #[arg(long = "in")]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
enum AttachCmd {
    /// Encrypt a file and attach it to an item.
    Add { item: String, path: PathBuf },
    /// List an item's attachments.
    List { item: String },
    /// Decrypt an attachment into a new file (mode 0600).
    Get {
        item: String,
        attachment_id: Uuid,
        out: PathBuf,
    },
    /// Remove an attachment from an item.
    Rm { item: String, attachment_id: Uuid },
}

#[derive(Args)]
struct AddArgs {
    /// Starting template: login, note, card or identity. Adds the matching tag.
    #[arg(long, default_value = "login", value_parser = ["login", "note", "card", "identity"])]
    template: String,
    #[arg(long)]
    title: String,
    #[arg(long)]
    username: Option<String>,
    /// Prompt for the item password (or read VAULT_ITEM_PASSWORD when --password-env is used).
    #[arg(long)]
    password_field: bool,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    notes: Option<String>,
    /// Insecure on shared machines (visible in ps/history); prefer --totp-field.
    #[arg(long, conflicts_with = "totp_field")]
    totp: Option<String>,
    /// Prompt for the TOTP URI (or read VAULT_ITEM_TOTP when --password-env is used).
    #[arg(long)]
    totp_field: bool,
    #[arg(long = "tag")]
    tags: Vec<String>,
}

#[derive(Args)]
struct EditArgs {
    /// Item id or title.
    id_or_title: String,
    #[arg(long)]
    title: Option<String>,
    #[arg(long, conflicts_with = "unfavorite")]
    favorite: bool,
    #[arg(long)]
    unfavorite: bool,
    /// Add a tag (repeatable).
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Remove a tag (repeatable).
    #[arg(long = "untag")]
    untags: Vec<String>,
    /// auto, symbol:<IconName>[:#RRGGBB] or letter:#RRGGBB.
    #[arg(long)]
    icon: Option<String>,
    /// Set a field value: <field-id-or-name>=<value> (repeatable). A new name creates a text
    /// field; a name shared by several fields is refused, use the id (`vault get --ids`).
    #[arg(long = "set", value_name = "FIELD=VALUE")]
    sets: Vec<String>,
    /// Like --set, but the value is read from the environment variable: <field>=<ENVVAR>.
    #[arg(long = "set-env", value_name = "FIELD=ENVVAR")]
    set_envs: Vec<String>,
    /// Add a field: <kind>:<name>[=<value>]; kinds text, password, url, notes, email, section.
    #[arg(long = "add", value_name = "KIND:NAME[=VALUE]")]
    adds: Vec<String>,
    /// Remove the field with this id (repeatable).
    #[arg(long = "rm-field", value_name = "FIELD_ID")]
    rm_fields: Vec<Uuid>,
}

#[derive(Args)]
struct GenArgs {
    #[arg(long, default_value_t = 20)]
    length: usize,
    #[arg(long)]
    no_symbols: bool,
    #[arg(long)]
    no_digits: bool,
    #[arg(long)]
    no_upper: bool,
    #[arg(long)]
    passphrase: bool,
    #[arg(long, default_value_t = 4, requires = "passphrase")]
    words: usize,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn device_id() -> Result<Uuid> {
    vault_macos::try_device_id().context("resolving device id")
}

/// Create a new file readable only by the owner; fails if it already exists.
fn create_private(path: &Path) -> Result<fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// Atomically replace `path` with `bytes`: write a fresh 0600 temp file in the same
/// directory, fsync it, then rename over `path`. Refuses to replace a symlink.
fn replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        bail!("refusing to overwrite a symlink: {}", path.display());
    }
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path.file_name().context("output path has no file name")?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = dir.join(format!(
        ".{}.tmp-{}-{nanos}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut f = create_private(&tmp)?;
    let result = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .with_context(|| format!("writing {}", tmp.display()))
        .and_then(|()| {
            fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
        });
    if result.is_err() {
        drop(f);
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Escape characters that could act on a terminal when vault content is printed.
/// C0 controls, DEL, C1 controls and bidi/format controls become `\u{XXXX}`;
/// tab becomes a single space and line feed is kept.
fn sanitize_for_terminal(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' => out.push(' '),
            '\n' => out.push('\n'),
            '\u{0}'..='\u{1f}'
            | '\u{7f}'
            | '\u{80}'..='\u{9f}'
            | '\u{61c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{206a}'..='\u{206f}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}' => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            _ => out.push(c),
        }
    }
    out
}

/// First non-section field whose name matches `name` in ASCII case. Sections are headings,
/// never data, so a crafted section name must not shadow or stand in for a real field.
fn named_field<'a>(item: &'a Item, name: &str) -> Option<&'a Field> {
    item.fields
        .iter()
        .find(|f| f.kind != FieldKind::Section && f.name.eq_ignore_ascii_case(name))
}

/// The field the `totp` command reads: one named "totp", else the first of kind Totp.
fn totp_field(item: &Item) -> Option<&Field> {
    named_field(item, "totp").or_else(|| item.fields.iter().find(|f| f.kind == FieldKind::Totp))
}

/// The username shown in the `list` column: a non-sensitive field named "username" in any ASCII case.
fn list_username(item: &Item) -> Option<String> {
    named_field(item, "username")
        .filter(|f| !f.kind.is_sensitive())
        .map(|f| sanitize_for_terminal(f.value.expose_secret()))
        .filter(|u| !u.is_empty())
}

/// Unix milliseconds as `YYYY-MM-DD HH:MM:SS UTC` (Hinnant's civil-from-days; no dependency).
/// Every `u64` input is representable, so nothing can overflow.
fn format_utc(millis: u64) -> String {
    let secs = millis / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The trailing `get` lines: `Created:` (when known) above `Modified:`.
fn stamp_lines(item: &Item) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(c) = item.created_at {
        lines.push(format!("Created: {}", format_utc(c)));
    }
    lines.push(format!("Modified: {}", format_utc(item.modified_at)));
    lines
}

/// One `get` output line for a field. A section is a bare uppercased heading with no value.
/// An empty name keeps the `name: value` shape (`: value`), so a value can never pass for a
/// heading or another labelled line. With `show_id`, the field id trails.
fn field_line(item: &Item, f: &Field, reveal: bool, show_id: bool) -> String {
    let mut line = if f.kind == FieldKind::Section {
        sanitize_for_terminal(&f.name.to_uppercase())
    } else {
        format!(
            "{}: {}",
            sanitize_for_terminal(&f.name),
            display_value(item, f, reveal)
        )
    };
    if show_id {
        line.push_str(&format!("  (id {})", f.id));
    }
    line
}

/// What `vault sync` prints for the events it drained. Every line is terminal-safe: conflict
/// copy names come from other devices and providers.
struct SyncReport {
    lines: Vec<String>,
    problems: Vec<String>,
    absorbed: usize,
}

fn sync_report(events: impl Iterator<Item = vault_sync::SyncEvent>) -> SyncReport {
    use vault_sync::SyncEvent;
    let mut r = SyncReport {
        lines: Vec::new(),
        problems: Vec::new(),
        absorbed: 0,
    };
    for ev in events {
        match ev {
            SyncEvent::ConflictAbsorbed(p) => {
                r.absorbed += 1;
                r.lines.push(format!(
                    "absorbed conflict copy -> {}",
                    sanitize_for_terminal(&p.display().to_string())
                ));
            }
            SyncEvent::Merged(m) => r.lines.push(format!(
                "merged: {} added, {} updated, {} deleted, {} unchanged{}",
                m.added,
                m.updated,
                m.deleted,
                m.unchanged,
                if m.header_updated {
                    ", header updated"
                } else {
                    ""
                }
            )),
            SyncEvent::ForeignVault => r
                .lines
                .push("note: a different vault sits next to this one; left alone".to_owned()),
            SyncEvent::Error(m) => r
                .problems
                .push(sanitize_for_terminal(&format!("error: {m}"))),
            SyncEvent::KeyMismatch | SyncEvent::KeyRotatedOnDisk => r
                .problems
                .push("the vault on disk no longer opens with this key".to_owned()),
            SyncEvent::SaveBlocked(b) => r
                .problems
                .push(sanitize_for_terminal(&format!("save blocked: {b:?}"))),
            SyncEvent::CloudUnavailable => r
                .problems
                .push("cloud copy not downloaded in time".to_owned()),
            _ => {}
        }
    }
    r
}

/// Hint for `list`/`get` when the vault file is older than this build writes.
fn format_hint(v: &UnlockedVault) -> Option<&'static str> {
    (v.header().format_version < FORMAT_VERSION).then_some("Vault is format 1; run `vault upgrade`")
}

/// What `get` prints for a field: secrets are masked unless `reveal` is set.
fn display_value(item: &Item, f: &Field, reveal: bool) -> String {
    let raw = f.value.expose_secret();
    if reveal {
        return sanitize_for_terminal(raw);
    }
    if f.name.eq_ignore_ascii_case("number")
        && item.tags.iter().any(|t| t.eq_ignore_ascii_case("card"))
    {
        let digits: Vec<char> = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if digits.len() >= 4 {
            let last4: String = digits[digits.len() - 4..].iter().collect();
            return format!(
                "\u{2022}\u{2022}\u{2022}\u{2022} \u{2022}\u{2022}\u{2022}\u{2022} \u{2022}\u{2022}\u{2022}\u{2022} {last4}"
            );
        }
        return "********".to_owned();
    }
    match f.kind {
        _ if f.kind.is_sensitive() => "********".to_owned(),
        _ => sanitize_for_terminal(raw),
    }
}

fn read_secret(prompt: &str) -> Result<SecretString> {
    Ok(SecretString::new(rpassword::prompt_password(prompt)?))
}

fn env_secret(var: &str) -> Result<SecretString> {
    match std::env::var(var) {
        Ok(v) => Ok(SecretString::new(v)),
        Err(_) => bail!("environment variable {var} is not set"),
    }
}

fn master_password(cli: &Cli, confirm: bool) -> Result<SecretString> {
    if let Some(var) = &cli.password_env {
        return env_secret(var);
    }
    let pw = read_secret("Master password: ")?;
    if confirm {
        let again = read_secret("Repeat master password: ")?;
        if pw.expose_secret() != again.expose_secret() {
            bail!("passwords do not match");
        }
    }
    Ok(pw)
}

fn vault_path(cli: &Cli) -> Result<PathBuf> {
    cli.vault
        .clone()
        .context("no vault path: pass --vault or set VAULT_FILE")
}

fn find_item(vault: &UnlockedVault, key: &str) -> Result<Uuid> {
    if let Ok(id) = key.parse::<Uuid>()
        && vault.get(id).is_some_and(|i| !i.is_deleted())
    {
        return Ok(id);
    }
    let lower = key.to_lowercase();
    let by_title: Vec<&Item> = vault
        .items()
        .filter(|i| i.title.to_lowercase() == lower)
        .collect();
    // An id prefix: at least 8 hex characters (hyphens do not count), what `list` prints.
    let hex_shaped = lower.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        && lower.bytes().filter(u8::is_ascii_hexdigit).count() >= 8;
    let by_prefix: Vec<&Item> = if hex_shaped {
        vault
            .items()
            .filter(|i| {
                if lower.contains('-') {
                    i.id.to_string().starts_with(&lower)
                } else {
                    i.id.simple().to_string().starts_with(&lower)
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    let ids = |items: &[&Item]| {
        items
            .iter()
            .map(|i| i.id.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };
    let shown = sanitize_for_terminal(key);
    match (by_title.as_slice(), by_prefix.as_slice()) {
        ([t], [p]) if t.id == p.id => Ok(t.id),
        ([], []) => bail!("no item matches \"{shown}\""),
        ([one], []) | ([], [one]) => Ok(one.id),
        (t, []) => bail!("ambiguous title \"{shown}\"; candidates:\n{}", ids(t)),
        ([], p) => bail!("ambiguous id prefix \"{shown}\"; candidates:\n{}", ids(p)),
        _ => bail!(
            "ambiguous: \"{shown}\" matches both a title and an id prefix; pass the full UUID"
        ),
    }
}

fn sync_err(e: SyncError) -> anyhow::Error {
    match e {
        SyncError::Vault(v) => v.into(),
        other => other.into(),
    }
}

fn open_synced(path: &Path, password: &SecretString) -> Result<SyncedVault> {
    let mut sv = SyncedVault::open(path, device_id()?, Arc::new(NoopHooks)).map_err(sync_err)?;
    sv.unlock(password).map_err(sync_err)?;
    Ok(sv)
}

fn open_cli(cli: &Cli) -> Result<SyncedVault> {
    let path = vault_path(cli)?;
    open_synced(&path, &master_password(cli, false)?)
}

fn synced_item(sv: &SyncedVault, key: &str) -> Result<Uuid> {
    find_item(sv.vault().context("vault is locked")?, key)
}

fn state_str(s: AttachmentState) -> &'static str {
    match s {
        AttachmentState::Present => "present",
        AttachmentState::NotDownloaded => "not-downloaded",
        AttachmentState::Missing => "missing",
    }
}

/// The attachment id that holds the item's custom image icon, if the icon is of kind `image`
/// and its value is a UUID. Such an attachment is an implementation detail and stays hidden.
fn icon_attachment_id(item: &Item) -> Option<Uuid> {
    let icon = item.icon.as_ref()?;
    if icon.kind != "image" {
        return None;
    }
    Uuid::parse_str(&icon.value).ok()
}

/// Text after `Icon: ` in `get` output (unsanitized).
fn icon_summary(item: &Item, icon: &ItemIcon) -> String {
    let color = icon.color.as_deref();
    match icon.kind.as_str() {
        "symbol" => match color {
            Some(c) => format!("symbol {} {c}", icon.value),
            None => format!("symbol {}", icon.value),
        },
        "letter" => match color {
            Some(c) => format!("letter {c}"),
            None => "letter".to_owned(),
        },
        "logo" => format!("logo {}", icon.value),
        "image" => match icon_attachment_id(item)
            .and_then(|id| item.attachments.iter().find(|a| a.id == id))
        {
            Some(a) => format!("image ({} bytes)", a.size),
            None => "image (blob missing)".to_owned(),
        },
        other => format!("{other} (unknown)"),
    }
}

/// Drop attachment `id` from `item`. When it is the item's icon image, also clear `item.icon`
/// so no dangling reference is written. Returns whether the icon was cleared.
fn remove_attachment_and_icon(
    v: &mut UnlockedVault,
    item: Uuid,
    id: Uuid,
    now: u64,
) -> Result<bool, VaultError> {
    let clears_icon = v
        .get(item)
        .is_some_and(|it| icon_attachment_id(it) == Some(id));
    v.remove_attachment_ref(item, id, now)?;
    if clears_icon {
        v.update(item, now, |it| it.icon = None)?;
    }
    Ok(clears_icon)
}

fn attach_get(sv: &SyncedVault, item: Uuid, id: Uuid, out: &Path) -> Result<()> {
    let known = sv
        .vault()
        .and_then(|v| v.get(item))
        .is_some_and(|it| it.attachments.iter().any(|a| a.id == id));
    if !known {
        bail!("attachment not found: {id}");
    }
    let mut reader = sv.open_attachment(item, id).map_err(sync_err)?;
    let mut f = create_private(out)?;
    let result = std::io::copy(&mut reader, &mut f)
        .map(drop)
        .and_then(|()| f.sync_all())
        .with_context(|| format!("writing {}", out.display()));
    if result.is_err() {
        drop(f);
        let _ = fs::remove_file(out);
    }
    result
}

fn run_attach(cli: &Cli, cmd: &AttachCmd) -> Result<()> {
    let path = vault_path(cli)?;
    let pw = master_password(cli, false)?;
    match cmd {
        AttachCmd::Add { item, path: src } => {
            let meta = fs::metadata(src).with_context(|| format!("reading {}", src.display()))?;
            if !meta.is_file() {
                bail!("{} is not a regular file", src.display());
            }
            if meta.len() > MAX_ATTACHMENT_SIZE {
                bail!("file is larger than 100 MB");
            }
            let name = src
                .file_name()
                .with_context(|| format!("{} has no file name", src.display()))?
                .to_string_lossy()
                .into_owned();
            let mut sv = open_synced(&path, &pw)?;
            let item = synced_item(&sv, item)?;
            let file = fs::File::open(src).with_context(|| format!("opening {}", src.display()))?;
            let id = sv
                .add_attachment(item, &name, file, meta.len(), now_millis())
                .map_err(sync_err)?;
            sv.save().map_err(sync_err)?;
            println!("{id}");
        }
        AttachCmd::List { item } => {
            let sv = open_synced(&path, &pw)?;
            let item = synced_item(&sv, item)?;
            let it = sv
                .vault()
                .and_then(|v| v.get(item))
                .context("item vanished")?;
            let hidden = icon_attachment_id(it);
            for a in it.attachments.iter().filter(|a| Some(a.id) != hidden) {
                println!(
                    "{}  {}  {}  {}",
                    a.id,
                    sanitize_for_terminal(&a.name),
                    a.size,
                    state_str(sv.attachment_state(a.id))
                );
            }
        }
        AttachCmd::Get {
            item,
            attachment_id,
            out,
        } => {
            let sv = open_synced(&path, &pw)?;
            let item = synced_item(&sv, item)?;
            attach_get(&sv, item, *attachment_id, out)?;
            println!("wrote {}", out.display());
        }
        AttachCmd::Rm {
            item,
            attachment_id,
        } => {
            let mut sv = open_synced(&path, &pw)?;
            let item = synced_item(&sv, item)?;
            let now = now_millis();
            let clears_icon = sv
                .edit(|v| remove_attachment_and_icon(v, item, *attachment_id, now))
                .map_err(sync_err)??;
            sv.save().map_err(sync_err)?;
            println!("removed {attachment_id}");
            if clears_icon {
                println!("this was the item's icon image; the icon was cleared");
            }
        }
    }
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Cmd::Attach { cmd } => run_attach(&cli, cmd)?,
        Cmd::Gen(a) => {
            if a.passphrase {
                if a.words < 1 {
                    bail!("words must be at least 1");
                }
            } else {
                // Lowercase is always on; each other enabled class needs one character.
                let min = 1
                    + usize::from(!a.no_symbols)
                    + usize::from(!a.no_digits)
                    + usize::from(!a.no_upper);
                if a.length < min {
                    bail!("length must be at least {min} for the enabled character classes");
                }
            }
            let secret = if a.passphrase {
                passphrase(&PassphraseSpec {
                    words: a.words,
                    ..PassphraseSpec::default()
                })
            } else {
                password(&PasswordSpec {
                    length: a.length,
                    symbols: !a.no_symbols,
                    digits: !a.no_digits,
                    upper: !a.no_upper,
                    ..PasswordSpec::default()
                })
            };
            println!("{}", secret.expose_secret());
        }
        Cmd::Init {
            kdf_test_params,
            allow_weak,
        } => {
            let path = vault_path(&cli)?;
            let pw = master_password(&cli, true)?;
            if !*allow_weak {
                let bits = strength_bits(pw.expose_secret());
                if bits < 50.0 {
                    bail!(
                        "master password too weak ({bits:.0} bits, minimum 50). Use a 4-word passphrase, or pass --allow-weak."
                    );
                }
            }
            let kdf = if *kdf_test_params {
                KdfParams::for_tests()
            } else {
                let k = KdfParams::calibrate(Duration::from_millis(500));
                println!(
                    "KDF: m={} KiB, t={}, p={}",
                    k.m_cost_kib, k.t_cost, k.p_cost
                );
                k
            };
            SyncedVault::create(&path, &pw, kdf, device_id()?, Arc::new(NoopHooks))
                .map_err(sync_err)?;
            println!("created {}", path.display());
        }
        Cmd::Add(a) => {
            let path = vault_path(&cli)?;
            let pw = master_password(&cli, false)?;
            let item_pw = if a.password_field {
                Some(if cli.password_env.is_some() {
                    env_secret("VAULT_ITEM_PASSWORD")?
                } else {
                    read_secret("Item password: ")?
                })
            } else {
                None
            };
            let totp_uri: Option<SecretString> = if a.totp_field {
                Some(if cli.password_env.is_some() {
                    env_secret("VAULT_ITEM_TOTP")?
                } else {
                    read_secret("TOTP otpauth URI: ")?
                })
            } else {
                a.totp.clone().map(SecretString::new)
            };
            if let Some(uri) = &totp_uri {
                Totp::parse_uri(uri.expose_secret())
                    .map_err(|e| anyhow::anyhow!("invalid totp URI: {e}"))?;
            }
            let mut sv = open_synced(&path, &pw)?;
            let now = now_millis();
            let mut item = Item::new(a.title.clone(), sv.device_id(), now);
            item.tags = a.tags.clone();
            if !item
                .tags
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&a.template))
            {
                item.tags.push(a.template.clone());
            }
            match a.template.as_str() {
                "login" => {
                    if a.username.is_none() {
                        item.fields.push(Field::new(
                            "username",
                            FieldKind::Text,
                            SecretString::new(String::new()),
                            now,
                        ));
                    }
                    if item_pw.is_none() {
                        item.fields.push(Field::new(
                            "password",
                            FieldKind::Password,
                            SecretString::new(String::new()),
                            now,
                        ));
                    }
                }
                "note" if a.notes.is_none() => item.fields.push(Field::new(
                    "notes",
                    FieldKind::Notes,
                    SecretString::new(String::new()),
                    now,
                )),
                _ => {}
            }
            let mut push = |name: &str, kind: FieldKind, v: SecretString| {
                item.fields.push(Field::new(name, kind, v, now));
            };
            if let Some(v) = &a.username {
                push("username", FieldKind::Text, SecretString::new(v.clone()));
            }
            if let Some(v) = item_pw {
                push("password", FieldKind::Password, v);
            }
            if let Some(v) = &a.url {
                push("url", FieldKind::Url, SecretString::new(v.clone()));
            }
            if let Some(v) = &a.notes {
                push("notes", FieldKind::Notes, SecretString::new(v.clone()));
            }
            if let Some(v) = totp_uri {
                push("totp", FieldKind::Totp, v);
            }
            let id = sv.edit(|v| v.insert(item, now)).map_err(sync_err)?;
            sv.save().map_err(sync_err)?;
            println!("{id}");
        }
        Cmd::Get {
            id_or_title,
            reveal,
            ids,
        } => {
            let sv = open_cli(&cli)?;
            let vault = sv.vault().context("vault is locked")?;
            if let Some(h) = format_hint(vault) {
                eprintln!("{h}");
            }
            let item = vault
                .get(find_item(vault, id_or_title)?)
                .context("item vanished")?;
            println!("id:    {}", item.id);
            println!("title: {}", sanitize_for_terminal(&item.title));
            println!("tags:  {}", sanitize_for_terminal(&item.tags.join(", ")));
            if *ids {
                println!("Device: {}", item.device_id);
            }
            if let Some(icon) = &item.icon {
                println!("Icon: {}", sanitize_for_terminal(&icon_summary(item, icon)));
            }
            for f in &item.fields {
                println!("{}", field_line(item, f, *reveal, *ids));
            }
            for line in stamp_lines(item) {
                println!("{line}");
            }
        }
        Cmd::List {
            tag,
            favorites,
            query,
        } => {
            let sv = open_cli(&cli)?;
            let vault = sv.vault().context("vault is locked")?;
            if let Some(h) = format_hint(vault) {
                eprintln!("{h}");
            }
            let q = Query {
                text: query.as_deref().unwrap_or(""),
                tag: tag.as_deref(),
                favorites_only: *favorites,
            };
            for item in search(vault, &q) {
                let short = &item.id.simple().to_string()[..8];
                let user = list_username(item);
                let tags = sanitize_for_terminal(&item.tags.join(","));
                let title = sanitize_for_terminal(&item.title);
                match user {
                    Some(u) => println!("{short}  {title}  {u}  [{tags}]"),
                    None => println!("{short}  {title}  [{tags}]"),
                }
            }
        }
        Cmd::Edit(a) => {
            let mut plan = edit::EditPlan {
                title: a.title.clone(),
                favorite: if a.favorite {
                    Some(true)
                } else if a.unfavorite {
                    Some(false)
                } else {
                    None
                },
                tags_add: a.tags.clone(),
                tags_rm: a.untags.clone(),
                icon: a.icon.as_deref().map(edit::parse_icon).transpose()?,
                rm_fields: a.rm_fields.clone(),
                ..Default::default()
            };
            for s in &a.sets {
                let (t, v) = edit::parse_target(s)?;
                plan.sets.push((t, SecretString::new(v)));
            }
            for s in &a.set_envs {
                let (key, var) = s
                    .split_once('=')
                    .context("--set-env expects <field>=<ENVVAR>")?;
                plan.sets
                    .push((edit::parse_field_ref(key)?, env_secret(var)?));
            }
            for s in &a.adds {
                plan.adds.push(edit::parse_add(s)?);
            }
            if plan.is_empty() {
                bail!("nothing to edit: pass at least one edit flag");
            }
            let path = vault_path(&cli)?;
            let pw = master_password(&cli, false)?;
            let mut sv = open_synced(&path, &pw)?;
            let item = synced_item(&sv, &a.id_or_title)?;
            sv.edit(|v| edit::apply(v, item, &plan, now_millis()))
                .map_err(sync_err)??;
            sv.save().map_err(sync_err)?;
            println!("updated {item}");
        }
        Cmd::Sync => {
            let path = vault_path(&cli)?;
            let pw = master_password(&cli, false)?;
            let mut sv = open_synced(&path, &pw)?;
            let rx = sv.subscribe();
            let run = sv.start_watching().map_err(sync_err).and_then(|()| {
                sv.poll();
                if sv.is_dirty() {
                    sv.save().map_err(sync_err)?;
                }
                Ok(())
            });
            // Always stop the watcher and report what was queued, even when a step failed.
            sv.stop_watching();
            let report = sync_report(rx.try_iter());
            for line in &report.lines {
                println!("{line}");
            }
            for p in &report.problems {
                eprintln!("{p}");
            }
            run?;
            if !report.problems.is_empty() {
                bail!("not converged");
            }
            println!("synced: {} conflict copies absorbed", report.absorbed);
        }
        Cmd::Upgrade { allow_weak } => {
            let path = vault_path(&cli)?;
            let pw = master_password(&cli, false)?;
            let mut sv = open_synced(&path, &pw)?;
            let version = sv
                .vault()
                .context("vault is locked")?
                .header()
                .format_version;
            if version >= FORMAT_VERSION {
                println!("already at version {FORMAT_VERSION}");
            } else {
                if !*allow_weak && strength_bits(pw.expose_secret()) < 50.0 {
                    eprintln!(
                        "warning: master password is under 50 bits of strength; pass --allow-weak to silence this"
                    );
                }
                sv.edit(|v| v.upgrade_format(&pw, now_millis()))
                    .map_err(sync_err)??;
                sv.save().map_err(sync_err)?;
                println!("upgraded to version {FORMAT_VERSION}");
                println!("Non-password key slots were dropped; re-enable Touch ID in the app.");
            }
        }
        Cmd::Rm { id_or_title } => {
            let mut sv = open_cli(&cli)?;
            let id = synced_item(&sv, id_or_title)?;
            sv.edit(|v| v.delete(id, now_millis()))
                .map_err(sync_err)?
                .map_err(anyhow::Error::from)?;
            sv.save().map_err(sync_err)?;
            println!("deleted {id}");
        }
        Cmd::Totp { id_or_title } => {
            let sv = open_cli(&cli)?;
            let vault = sv.vault().context("vault is locked")?;
            let item = vault
                .get(find_item(vault, id_or_title)?)
                .context("item vanished")?;
            let field = totp_field(item).context("item has no totp field")?;
            let raw = field.value.expose_secret();
            let totp = if raw.starts_with("otpauth://") {
                Totp::parse_uri(raw)
            } else {
                Totp::from_secret_base32(raw)
            }
            .map_err(|e| anyhow::anyhow!("invalid totp secret: {e}"))?;
            let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            println!(
                "{} ({}s remaining)",
                sanitize_for_terminal(&totp.code(secs)),
                totp.seconds_remaining(secs)
            );
        }
        Cmd::Export { out, yes, force } => {
            if !*yes {
                bail!("export writes ALL secrets in plaintext; re-run with --yes to confirm");
            }
            let sv = open_cli(&cli)?;
            let vault = sv.vault().context("vault is locked")?;
            let export = export_csv(vault);
            if *force {
                replace_private(out, &export.0)?;
            } else {
                let mut f =
                    create_private(out).context("use --force to overwrite an existing file")?;
                f.write_all(&export.0)
                    .with_context(|| format!("writing {}", out.display()))?;
            }
            // Warn only after the file is written: a closed stderr must not end the program
            // before the export exists.
            eprintln!(
                "WARNING: writing UNENCRYPTED passwords and secrets to {}",
                out.display()
            );
            eprintln!(
                "WARNING: anyone who can read that file can read every secret. Delete it after use."
            );
            println!("exported to {}", out.display());
        }
        Cmd::Import { format, input } => {
            if format != "csv" {
                bail!("unsupported format {format:?}");
            }
            let mut sv = open_cli(&cli)?;
            let bytes = fs::read(input).with_context(|| format!("reading {}", input.display()))?;
            let now = now_millis();
            let items = import_csv(&bytes, &CsvMapping::default(), sv.device_id(), now)?;
            let count = items.len();
            sv.edit(|v| {
                for item in items {
                    v.insert(item, now);
                }
            })
            .map_err(sync_err)?;
            sv.save().map_err(sync_err)?;
            println!("imported {count} items");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if matches!(
                e.downcast_ref::<VaultError>(),
                Some(VaultError::WrongPassword)
            ) {
                eprintln!("wrong password");
                return ExitCode::from(2);
            }
            if matches!(
                e.downcast_ref::<VaultError>(),
                Some(VaultError::NoUsableSlot)
            ) {
                eprintln!(
                    "this vault was created by a newer version of vault with an unlock method this version does not support"
                );
                return ExitCode::FAILURE;
            }
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_escapes_controls_and_format_chars() {
        assert_eq!(sanitize_for_terminal("a\tb"), "a b");
        assert_eq!(sanitize_for_terminal("a\nb"), "a\nb");
        assert_eq!(sanitize_for_terminal("a\rb"), "a\\u{d}b");
        assert_eq!(sanitize_for_terminal("\u{9b}31m"), "\\u{9b}31m");
        assert_eq!(sanitize_for_terminal("a\u{2028}b"), "a\\u{2028}b");
        assert_eq!(sanitize_for_terminal("\u{feff}x"), "\\u{feff}x");
        for c in [
            '\u{61c}', '\u{180e}', '\u{206a}', '\u{206f}', '\u{fff9}', '\u{fffb}',
        ] {
            let out = sanitize_for_terminal(&c.to_string());
            assert!(out.starts_with("\\u{"), "{c:?} -> {out}");
        }
        assert_eq!(
            sanitize_for_terminal("Plain \u{e9}\u{4e16}"),
            "Plain \u{e9}\u{4e16}"
        );
    }

    fn item(card: bool, fname: &str, fkind: FieldKind, v: &str) -> Item {
        let mut i = Item::new("t", Uuid::nil(), 0);
        if card {
            i.tags.push("card".to_owned());
        }
        i.fields
            .push(Field::new(fname, fkind, SecretString::new(v.to_owned()), 0));
        i
    }

    #[test]
    fn masks_totp_and_password() {
        let uri = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
        let i = item(false, "totp", FieldKind::Totp, uri);
        assert_eq!(display_value(&i, &i.fields[0], false), "********");
        assert_eq!(display_value(&i, &i.fields[0], true), uri);
        let i = item(false, "password", FieldKind::Password, "pw");
        assert_eq!(display_value(&i, &i.fields[0], false), "********");
    }

    #[test]
    fn masks_card_number_to_last4() {
        let i = item(true, "number", FieldKind::Text, "4111 1111 1111 1234");
        let masked = display_value(&i, &i.fields[0], false);
        assert!(
            masked.ends_with(" 1234") && !masked.contains("4111"),
            "{masked}"
        );
        assert_eq!(display_value(&i, &i.fields[0], true), "4111 1111 1111 1234");
        let short = item(true, "number", FieldKind::Text, "12");
        assert_eq!(display_value(&short, &short.fields[0], false), "********");
    }

    fn with_icon(kind: &str, value: &str, color: Option<&str>) -> Item {
        let mut i = Item::new("t", Uuid::nil(), 0);
        let mut icon = ItemIcon::new(kind, value);
        icon.color = color.map(str::to_owned);
        i.icon = Some(icon);
        i
    }

    fn icon_line(i: &Item) -> String {
        sanitize_for_terminal(&icon_summary(i, i.icon.as_ref().unwrap()))
    }

    fn add_blob(i: &mut Item, size: u64) -> Uuid {
        let r = vault_core::attachment::new_ref("pic.png", size, 1).unwrap();
        let id = r.id;
        i.attachments.push(r);
        id
    }

    fn test_vault() -> UnlockedVault {
        UnlockedVault::create(
            &SecretString::new("pw".to_owned()),
            KdfParams::for_tests(),
            Uuid::nil(),
        )
    }

    #[test]
    fn icon_attachment_id_only_for_valid_image() {
        let id = Uuid::new_v4();
        let i = with_icon("image", &id.to_string(), None);
        assert_eq!(icon_attachment_id(&i), Some(id));
        assert_eq!(
            icon_attachment_id(&with_icon("image", "not-a-uuid", None)),
            None
        );
        assert_eq!(
            icon_attachment_id(&with_icon("logo", &id.to_string(), None)),
            None
        );
        assert_eq!(icon_attachment_id(&Item::new("t", Uuid::nil(), 0)), None);
    }

    #[test]
    fn icon_lines_for_every_kind() {
        let i = with_icon("symbol", "star", Some("#112233"));
        assert_eq!(icon_line(&i), "symbol star #112233");
        assert_eq!(icon_line(&with_icon("symbol", "star", None)), "symbol star");
        assert_eq!(
            icon_line(&with_icon("letter", "", Some("#AABBCC"))),
            "letter #AABBCC"
        );
        assert_eq!(icon_line(&with_icon("logo", "github", None)), "logo github");
        let mut i = with_icon("image", "x", None);
        let id = add_blob(&mut i, 42);
        i.icon = Some(ItemIcon::new("image", id.to_string()));
        assert_eq!(icon_line(&i), "image (42 bytes)");
        let gone = with_icon("image", &Uuid::new_v4().to_string(), None);
        assert_eq!(icon_line(&gone), "image (blob missing)");
        assert_eq!(
            icon_line(&with_icon("image", "not-a-uuid", None)),
            "image (blob missing)"
        );
        assert_eq!(
            icon_line(&with_icon("hologram", "x", None)),
            "hologram (unknown)"
        );
        assert_eq!(
            icon_line(&with_icon("ev\u{1b}il", "x", None)),
            "ev\\u{1b}il (unknown)"
        );
    }

    #[test]
    fn malformed_image_value_keeps_attachments_visible_and_icon_on_removal() {
        let mut v = test_vault();
        let mut i = with_icon("image", "not-a-uuid", None);
        let a = add_blob(&mut i, 3);
        let item = v.insert(i, 10);
        let cleared = remove_attachment_and_icon(&mut v, item, a, 20).unwrap();
        assert!(!cleared);
        assert!(v.get(item).unwrap().icon.is_some());
    }

    #[test]
    fn removing_icon_attachment_by_id_clears_icon() {
        let mut v = test_vault();
        let mut i = Item::new("t", Uuid::nil(), 0);
        let icon_blob = add_blob(&mut i, 5);
        let other = add_blob(&mut i, 6);
        i.icon = Some(ItemIcon::new("image", icon_blob.to_string()));
        let item = v.insert(i, 10);
        // Listing hides only the icon blob.
        let it = v.get(item).unwrap();
        let hidden = icon_attachment_id(it);
        let visible: Vec<Uuid> = it
            .attachments
            .iter()
            .filter(|a| Some(a.id) != hidden)
            .map(|a| a.id)
            .collect();
        assert_eq!(visible, vec![other]);
        // Removing a normal attachment leaves the icon alone.
        assert!(!remove_attachment_and_icon(&mut v, item, other, 20).unwrap());
        assert!(v.get(item).unwrap().icon.is_some());
        // Removing the icon blob by id clears the icon.
        assert!(remove_attachment_and_icon(&mut v, item, icon_blob, 30).unwrap());
        let it = v.get(item).unwrap();
        assert!(it.icon.is_none() && it.attachments.is_empty());
    }

    #[test]
    fn capitalised_names_mask_and_match() {
        let i = item(true, "Number", FieldKind::Text, "4111 1111 1111 1234");
        let masked = display_value(&i, &i.fields[0], false);
        assert!(
            masked.ends_with(" 1234") && !masked.contains("4111"),
            "{masked}"
        );
        assert_eq!(display_value(&i, &i.fields[0], true), "4111 1111 1111 1234");
        let mut t = item(false, "Number", FieldKind::Text, "4111111111111234");
        t.tags.push("Card".to_owned());
        assert!(!display_value(&t, &t.fields[0], false).contains("4111"));
        let u = item(false, "Username", FieldKind::Text, "octo");
        assert_eq!(list_username(&u).as_deref(), Some("octo"));
    }

    #[test]
    fn section_renders_as_heading() {
        let i = item(false, "Login \u{1b}[31mdetails", FieldKind::Section, "");
        let line = field_line(&i, &i.fields[0], true, false);
        assert_eq!(line, "LOGIN \\u{1b}[31MDETAILS");
        assert!(!line.contains(':') && !line.contains("hidden"));
        let plain = item(false, "Work", FieldKind::Section, "");
        assert_eq!(field_line(&plain, &plain.fields[0], false, false), "WORK");
    }

    #[test]
    fn format_utc_known_values() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(86_399_999), "1970-01-01 23:59:59 UTC");
        assert_eq!(format_utc(951_782_400_000), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_utc(1_700_000_000_000), "2023-11-14 22:13:20 UTC");
        assert!(format_utc(u64::MAX).ends_with(" UTC"));
    }

    #[test]
    fn stamp_lines_order_and_presence() {
        let mut i = Item::new("t", Uuid::nil(), 1_700_000_000_000);
        i.created_at = Some(0);
        assert_eq!(
            stamp_lines(&i),
            [
                "Created: 1970-01-01 00:00:00 UTC",
                "Modified: 2023-11-14 22:13:20 UTC"
            ]
        );
        i.created_at = None;
        assert_eq!(stamp_lines(&i), ["Modified: 2023-11-14 22:13:20 UTC"]);
    }

    #[test]
    fn sections_never_satisfy_name_lookups() {
        let mut i = item(false, "Username", FieldKind::Section, "SHOULD-NOT-SHOW");
        assert_eq!(list_username(&i), None);
        i.fields.push(Field::new(
            "username",
            FieldKind::Text,
            SecretString::new("octo".to_owned()),
            0,
        ));
        assert_eq!(list_username(&i).as_deref(), Some("octo"));

        let uri = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
        let mut t = item(false, "totp", FieldKind::Section, "junk");
        t.fields.push(Field::new(
            "Authenticator",
            FieldKind::Totp,
            SecretString::new(uri.to_owned()),
            0,
        ));
        let f = totp_field(&t).unwrap();
        assert_eq!(f.kind, FieldKind::Totp);
        assert_eq!(f.value.expose_secret(), uri);
        assert!(totp_field(&item(false, "totp", FieldKind::Section, "x")).is_none());
    }

    #[test]
    fn empty_name_keeps_label_shape_and_ids_trail() {
        let i = item(false, "", FieldKind::Text, "just-a-value");
        let f = &i.fields[0];
        assert_eq!(field_line(&i, f, false, false), ": just-a-value");
        assert_eq!(
            field_line(&i, f, false, true),
            format!(": just-a-value  (id {})", f.id)
        );
        for v in ["LOGIN DETAILS", "password: hunter2"] {
            let e = item(false, "", FieldKind::Text, v);
            let line = field_line(&e, &e.fields[0], false, false);
            assert_eq!(line, format!(": {v}"));
            assert!(line.starts_with(": "));
        }
        let masked = item(false, "", FieldKind::Password, "hunter2");
        assert_eq!(
            field_line(&masked, &masked.fields[0], false, false),
            ": ********"
        );
        assert_eq!(
            field_line(&masked, &masked.fields[0], true, false),
            ": hunter2"
        );
        let named = item(false, "user", FieldKind::Text, "v");
        assert_eq!(
            field_line(&named, &named.fields[0], false, false),
            "user: v"
        );
    }

    #[test]
    fn sync_report_escapes_paths_and_collects_problems() {
        use vault_sync::SyncEvent;
        let r = sync_report(
            vec![
                SyncEvent::ConflictAbsorbed(PathBuf::from("/x/conflict-\u{1b}[31mred.bin")),
                SyncEvent::Error("bad \u{1b}[2J".to_owned()),
                SyncEvent::KeyRotatedOnDisk,
            ]
            .into_iter(),
        );
        assert_eq!(r.absorbed, 1);
        let all = format!("{:?}{:?}", r.lines, r.problems);
        assert!(!all.contains('\u{1b}'), "{all}");
        assert!(r.lines[0].contains("\\u{1b}[31mred"));
        assert_eq!(r.problems.len(), 2);
    }

    #[test]
    fn find_item_accepts_unambiguous_id_prefixes() {
        let mut v = test_vault();
        let mut a = Item::new("Alpha", Uuid::nil(), 1);
        a.id = Uuid::parse_str("aaaaaaaa-1111-4111-8111-111111111111").unwrap();
        let mut b = Item::new("Beta", Uuid::nil(), 1);
        b.id = Uuid::parse_str("aaaaaaaa-2222-4222-8222-222222222222").unwrap();
        let mut c = Item::new("Gamma", Uuid::nil(), 1);
        c.id = Uuid::parse_str("cccccccc-3333-4333-8333-333333333333").unwrap();
        let (a, _b, c) = (v.insert(a, 1), v.insert(b, 1), v.insert(c, 1));
        assert_eq!(find_item(&v, "cccccccc").unwrap(), c);
        assert_eq!(find_item(&v, "CCCCCCCC33").unwrap(), c);
        assert_eq!(find_item(&v, "aaaaaaaa-1").unwrap(), a);
        let e = find_item(&v, "aaaaaaaa").unwrap_err().to_string();
        assert!(e.contains("ambiguous id prefix"), "{e}");
        assert!(
            find_item(&v, "cccccc").is_err(),
            "under 8 chars is not a prefix"
        );
        assert!(find_item(&v, "dddddddd").is_err());
        assert_eq!(find_item(&v, "alpha").unwrap(), a);
    }

    #[test]
    fn find_item_title_and_prefix_collision_and_hyphen_count() {
        let mut v = test_vault();
        let mut a = Item::new("Alpha", Uuid::nil(), 1);
        a.id = Uuid::parse_str("abcdef12-1111-4111-8111-111111111111").unwrap();
        let mut b = Item::new("abcdef12", Uuid::nil(), 1);
        b.id = Uuid::parse_str("99999999-2222-4222-8222-222222222222").unwrap();
        let (a, _b) = (v.insert(a, 1), v.insert(b, 1));
        let e = find_item(&v, "abcdef12").unwrap_err().to_string();
        assert!(
            e.contains("title and an id prefix") && e.contains("full UUID"),
            "{e}"
        );
        assert_eq!(find_item(&v, &a.to_string()).unwrap(), a);
        // Seven hex characters plus a hyphen is still too short.
        assert!(find_item(&v, "abcdef1-").is_err());
        assert!(find_item(&v, "abcdef1").is_err());
        // Ambiguity lists show ids only.
        let mut c = Item::new("Secret title", Uuid::nil(), 1);
        c.id = Uuid::parse_str("abcdef12-3333-4333-8333-333333333333").unwrap();
        v.insert(c, 1);
        let e = find_item(&v, "abcdef12-").unwrap_err().to_string();
        assert!(
            e.contains("ambiguous id prefix") && !e.contains("Secret title"),
            "{e}"
        );
    }
}
