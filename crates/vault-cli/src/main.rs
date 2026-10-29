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
    CsvMapping, ExposeSecret, Field, FieldKind, Item, ItemKind, KdfParams, LockedVault,
    PassphraseSpec, PasswordSpec, Query, SecretString, Totp, UnlockedVault, Uuid, VaultError,
    attachment::MAX_ATTACHMENT_SIZE, export_csv, import_csv, passphrase, password, search,
    strength_bits,
};
use vault_sync::{AttachmentState, NoopHooks, SyncError, SyncedVault};

#[derive(Parser)]
#[command(name = "vault", about = "Dev/debug CLI for the vault password manager")]
struct Cli {
    /// Path to the vault file.
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
    },
    /// List items.
    List {
        #[arg(long)]
        kind: Option<String>,
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
    #[arg(long)]
    kind: String,
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

fn load(path: &Path, password: &SecretString) -> Result<UnlockedVault> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let locked = LockedVault::parse(&bytes)?;
    let mut vault = locked.unlock(password)?;
    vault.set_device_id(device_id()?);
    Ok(vault)
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

fn store(path: &Path, vault: &UnlockedVault) -> Result<()> {
    let name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?
        .to_string_lossy();
    let suffix = &Uuid::new_v4().simple().to_string()[..8];
    let tmp = path.with_file_name(format!(".{name}.tmp-{suffix}"));
    let result = (|| -> Result<()> {
        let mut f = create_private(&tmp)?;
        f.write_all(&vault.serialize())
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // Best effort: make the rename durable.
    if let Some(parent) = path.parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(d) = fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// What `get` prints for a field: secrets are masked unless `reveal` is set.
fn display_value(item: &Item, f: &Field, reveal: bool) -> String {
    let raw = f.value.expose_secret();
    if reveal {
        return raw.clone();
    }
    if item.kind == ItemKind::Card && f.name == "number" {
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
        _ => raw.clone(),
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
    let hits: Vec<&Item> = vault
        .items()
        .filter(|i| i.title.to_lowercase() == lower)
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.id),
        [] => bail!("no item matches {key:?}"),
        many => {
            let list: Vec<String> = many
                .iter()
                .map(|i| format!("{} {}", i.id, i.title))
                .collect();
            bail!("ambiguous title {key:?}; candidates:\n{}", list.join("\n"))
        }
    }
}

fn parse_kind(s: &str) -> Result<ItemKind> {
    ItemKind::parse(s).with_context(|| format!("unknown kind {s:?} (login|note|card|identity)"))
}

/// Keep `VaultError` reachable for the exit-code mapping in `main`.
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

fn attach_get(sv: &SyncedVault, item: Uuid, id: Uuid, out: &Path) -> Result<()> {
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
            for a in &it.attachments {
                println!(
                    "{}  {}  {}  {}",
                    a.id,
                    a.name,
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
            sv.remove_attachment(item, *attachment_id, now_millis())
                .map_err(sync_err)?;
            sv.save().map_err(sync_err)?;
            println!("removed {attachment_id}");
        }
    }
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Cmd::Attach { cmd } => run_attach(&cli, cmd)?,
        Cmd::Gen(a) => {
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
            let vault = UnlockedVault::create(&pw, kdf, device_id()?);
            // Reserve the final path atomically; fails if it already exists.
            drop(create_private(&path)?);
            if let Err(e) = store(&path, &vault) {
                let _ = fs::remove_file(&path);
                return Err(e);
            }
            println!("created {}", path.display());
        }
        Cmd::Add(a) => {
            let path = vault_path(&cli)?;
            let kind = parse_kind(&a.kind)?;
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
            let mut vault = load(&path, &pw)?;
            let now = now_millis();
            let mut item = Item::new(kind, a.title.clone(), vault.device_id(), now);
            item.tags = a.tags.clone();
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
            let id = vault.insert(item, now);
            store(&path, &vault)?;
            println!("{id}");
        }
        Cmd::Get {
            id_or_title,
            reveal,
        } => {
            let path = vault_path(&cli)?;
            let vault = load(&path, &master_password(&cli, false)?)?;
            let item = vault
                .get(find_item(&vault, id_or_title)?)
                .context("item vanished")?;
            println!("id:    {}", item.id);
            println!("title: {}", item.title);
            println!("kind:  {}", item.kind_str());
            println!("tags:  {}", item.tags.join(", "));
            for f in &item.fields {
                println!("{}: {}", f.name, display_value(item, f, *reveal));
            }
        }
        Cmd::List {
            kind,
            tag,
            favorites,
            query,
        } => {
            let path = vault_path(&cli)?;
            let vault = load(&path, &master_password(&cli, false)?)?;
            let kind = kind.as_deref().map(parse_kind).transpose()?;
            let q = Query {
                text: query.as_deref().unwrap_or(""),
                kind,
                tag: tag.as_deref(),
                favorites_only: *favorites,
            };
            for item in search(&vault, &q) {
                let short = &item.id.simple().to_string()[..8];
                let user = item
                    .field("username")
                    .filter(|f| !f.kind.is_sensitive())
                    .map(|f| f.value.expose_secret().as_str())
                    .filter(|u| !u.is_empty());
                match user {
                    Some(u) => println!("{short}  {:<8}  {}  {u}", item.kind_str(), item.title),
                    None => println!("{short}  {:<8}  {}", item.kind_str(), item.title),
                }
            }
        }
        Cmd::Rm { id_or_title } => {
            let path = vault_path(&cli)?;
            let mut vault = load(&path, &master_password(&cli, false)?)?;
            let id = find_item(&vault, id_or_title)?;
            vault.delete(id, now_millis())?;
            store(&path, &vault)?;
            println!("deleted {id}");
        }
        Cmd::Totp { id_or_title } => {
            let path = vault_path(&cli)?;
            let vault = load(&path, &master_password(&cli, false)?)?;
            let item = vault
                .get(find_item(&vault, id_or_title)?)
                .context("item vanished")?;
            let field = item
                .fields
                .iter()
                .find(|f| f.name == "totp")
                .or_else(|| item.fields.iter().find(|f| f.kind == FieldKind::Totp))
                .context("item has no totp field")?;
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
                totp.code(secs),
                totp.seconds_remaining(secs)
            );
        }
        Cmd::Export { out, yes, force } => {
            if !*yes {
                bail!("export writes ALL secrets in plaintext; re-run with --yes to confirm");
            }
            let path = vault_path(&cli)?;
            let vault = load(&path, &master_password(&cli, false)?)?;
            eprintln!(
                "WARNING: writing UNENCRYPTED passwords and secrets to {}",
                out.display()
            );
            eprintln!(
                "WARNING: anyone who can read that file can read every secret. Delete it after use."
            );
            let export = export_csv(&vault);
            let mut f = if *force {
                let f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(out)
                    .with_context(|| format!("opening {}", out.display()))?;
                // `mode` only applies on creation; tighten a pre-existing file too.
                fs::set_permissions(out, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                    .with_context(|| format!("setting permissions on {}", out.display()))?;
                f
            } else {
                create_private(out).context("use --force to overwrite an existing file")?
            };
            f.write_all(&export.0)
                .with_context(|| format!("writing {}", out.display()))?;
            println!("exported to {}", out.display());
        }
        Cmd::Import { format, input } => {
            if format != "csv" {
                bail!("unsupported format {format:?}");
            }
            let path = vault_path(&cli)?;
            let mut vault = load(&path, &master_password(&cli, false)?)?;
            let bytes = fs::read(input).with_context(|| format!("reading {}", input.display()))?;
            let now = now_millis();
            let items = import_csv(&bytes, &CsvMapping::default(), vault.device_id(), now)?;
            let count = items.len();
            for item in items {
                vault.insert(item, now);
            }
            store(&path, &vault)?;
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

    fn item(kind: ItemKind, fname: &str, fkind: FieldKind, v: &str) -> Item {
        let mut i = Item::new(kind, "t", Uuid::nil(), 0);
        i.fields
            .push(Field::new(fname, fkind, SecretString::new(v.to_owned()), 0));
        i
    }

    #[test]
    fn masks_totp_and_password() {
        let uri = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
        let i = item(ItemKind::Login, "totp", FieldKind::Totp, uri);
        assert_eq!(display_value(&i, &i.fields[0], false), "********");
        assert_eq!(display_value(&i, &i.fields[0], true), uri);
        let i = item(ItemKind::Login, "password", FieldKind::Password, "pw");
        assert_eq!(display_value(&i, &i.fields[0], false), "********");
    }

    #[test]
    fn masks_card_number_to_last4() {
        let i = item(
            ItemKind::Card,
            "number",
            FieldKind::Text,
            "4111 1111 1111 1234",
        );
        let masked = display_value(&i, &i.fields[0], false);
        assert!(
            masked.ends_with(" 1234") && !masked.contains("4111"),
            "{masked}"
        );
        assert_eq!(display_value(&i, &i.fields[0], true), "4111 1111 1111 1234");
        let short = item(ItemKind::Card, "number", FieldKind::Text, "12");
        assert_eq!(display_value(&short, &short.fields[0], false), "********");
    }
}
