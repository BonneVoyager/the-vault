//! Settings ▸ Security ▸ "Copy diagnostics" (specs/05-ui.md §2.5, owner decision
//! 2026-11-12, option A).
//!
//! [`diagnostics_text`] is pure: it reads `AppState` and a [`Host`] snapshot and never
//! touches the OS. It prints no title, field, tag, path, device id, vault id, error text
//! (errors can carry paths) or key material.

use std::time::{SystemTime, UNIX_EPOCH};

use vault_core::SlotKind;
use vault_sync::{SyncLocation, SyncedVault};

use super::AppState;
use crate::text;

/// Toast after the copy.
pub const DIAGNOSTICS_COPIED: &str = "Diagnostics copied";

/// Facts that need the OS, gathered by [`Host::probe`] and injected in tests.
#[derive(Debug, Clone, Default)]
pub struct Host {
    pub macos_version: Option<String>,
    pub model: Option<String>,
    /// Classification of the open vault's location; the path itself is never kept.
    pub location: Option<SyncLocation>,
}

impl Host {
    pub fn probe(s: &AppState) -> Self {
        let location = s.vault_path.as_deref().map(|path| {
            let home = dirs::home_dir();
            vault_sync::classify_location(path, home.as_deref(), || vault_macos::is_in_icloud(path))
        });
        Self {
            macos_version: Some(vault_macos::os_version()),
            model: Some(vault_macos::model_identifier()),
            location,
        }
    }
}

/// The four kinds the spec names; a provider's raw folder prefix is never printed.
fn location_kind(location: &SyncLocation) -> &'static str {
    match location {
        SyncLocation::ICloudDrive => "iCloud Drive",
        SyncLocation::Provider(name) if name == "Dropbox" => "Dropbox",
        SyncLocation::Provider(_) => "other cloud",
        SyncLocation::Local => "local",
    }
}

fn yes_no(b: bool) -> String {
    if b { "yes" } else { "no" }.to_owned()
}

fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The plain-text block, one `key: value` per line in the spec's order.
pub fn diagnostics_text(s: &AppState, now: SystemTime, host: &Host) -> String {
    let vault: Option<&SyncedVault> = s.vault.as_ref();
    let unlocked = s.unlocked_vault();
    let none_open = vault.is_none() && s.vault_path.is_none();
    // Header facts need the unlocked vault; vault-sync exposes only the slots while locked.
    let absent = if none_open { "no vault open" } else { "locked" };
    let header = |v: Option<String>| v.unwrap_or_else(|| absent.to_owned());
    let open = |v: Option<String>| v.unwrap_or_else(|| "no vault open".to_owned());
    let unknown = |v: &Option<String>| v.clone().unwrap_or_else(|| "unknown".to_owned());
    let slots = vault.map(|v| v.locked_summary().slots);
    let has_slot = |f: fn(&SlotKind) -> bool| {
        open(
            slots
                .as_ref()
                .map(|slots| yes_no(slots.iter().any(|(_, k)| f(k)))),
        )
    };

    let mut lines: Vec<(&str, String)> = vec![
        ("app version", env!("CARGO_PKG_VERSION").to_owned()),
        (
            "format version",
            header(unlocked.map(|v| v.header().format_version.to_string())),
        ),
        ("macOS version", unknown(&host.macos_version)),
        ("Mac model", unknown(&host.model)),
        (
            "KDF",
            header(s.current_kdf().map(|k| {
                format!(
                    "Argon2id m={} KiB, t={}, p={}",
                    k.m_cost_kib, k.t_cost, k.p_cost
                )
            })),
        ),
    ];
    if let Some(secs) = s.kdf_seconds() {
        lines.push(("unlock time", format!("{secs:.2} s (measured KDF)")));
    }
    let location = if none_open {
        None
    } else {
        Some(
            host.location
                .as_ref()
                .map_or("unknown", location_kind)
                .to_owned(),
        )
    };
    lines.push(("location", open(location)));
    lines.push(("items", header(unlocked.map(|_| s.counts.all.to_string()))));
    lines.push((
        "trashed",
        header(unlocked.map(|_| s.counts.deleted.to_string())),
    ));
    let backups = vault.map(|_| match s.sync.backups_error {
        Some(_) => "unavailable".to_owned(),
        None => s.sync.backups.len().to_string(),
    });
    lines.push(("backups", open(backups)));
    lines.push(("dirty", open(vault.map(|v| yes_no(v.is_dirty())))));

    let stamp = |t: SystemTime| {
        format!(
            "{} ({})",
            text::date_time(t),
            text::relative(millis(now), millis(t))
        )
    };
    let when = s
        .sync
        .last_saved
        .map_or_else(|| "none this session".to_owned(), stamp);
    let result = match (s.sync.save_failing, s.sync.last_saved) {
        (true, _) => "last attempt failed",
        (false, Some(_)) => "ok",
        (false, None) => "n/a",
    };
    lines.push(("last save", format!("{when}, result: {result}")));

    let sync = s.sync.last_event.map_or_else(
        || "none this session".to_owned(),
        |(label, t)| format!("{label}, {}", stamp(t)),
    );
    lines.push(("last sync event", sync));
    let watcher = vault.map(|_| {
        if s.is_watching() {
            "running"
        } else {
            "stopped"
        }
        .to_owned()
    });
    lines.push(("watcher", open(watcher)));
    lines.push(("Touch ID slot", has_slot(|k| *k == SlotKind::Enclave)));
    lines.push((
        "passkey slot",
        has_slot(|k| matches!(k, SlotKind::Other(kind) if kind == "passkey")),
    ));
    lines.push(("Show Vault in Dock", yes_no(s.settings.show_in_dock)));
    let login = match s.login_item {
        None => "not running from an app bundle",
        Some(vault_macos::LoginItemStatus::Enabled) => "enabled",
        Some(vault_macos::LoginItemStatus::Disabled) => "disabled",
        Some(vault_macos::LoginItemStatus::RequiresApproval) => "requires approval",
        Some(vault_macos::LoginItemStatus::NotFound) => "not found",
        Some(vault_macos::LoginItemStatus::Unavailable) => "unavailable",
    };
    lines.push(("Launch at login", login.to_owned()));
    lines.push(("appearance", s.settings.appearance.label().to_owned()));
    lines.push(("text size", s.settings.text_size.label().to_owned()));

    lines
        .into_iter()
        .map(|(k, v)| format!("{k}: {v}\n"))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use gpui::{AppContext as _, TestAppContext};
    use vault_core::{Field, FieldKind, Item, KdfParams, SecretString, Uuid};
    use vault_sync::NoopHooks;

    use super::super::SyncStatus;
    use super::*;

    const KEYS: [&str; 19] = [
        "app version",
        "format version",
        "macOS version",
        "Mac model",
        "KDF",
        "location",
        "items",
        "trashed",
        "backups",
        "dirty",
        "last save",
        "last sync event",
        "watcher",
        "Touch ID slot",
        "passkey slot",
        "Show Vault in Dock",
        "Launch at login",
        "appearance",
        "text size",
    ];

    fn keys(text: &str) -> Vec<&str> {
        text.lines()
            .map(|l| l.split_once(": ").expect("key: value").0)
            .collect()
    }

    fn expected(with_unlock_time: bool) -> Vec<&'static str> {
        let mut k = KEYS.to_vec();
        if with_unlock_time {
            k.insert(5, "unlock time");
        }
        k
    }

    const SECRETS: [&str; 6] = [
        "Zephyrine Bank",
        "Quillfeather Mail",
        "Trashed Marmalade",
        "alice.quux@example.org",
        "hunter2-Vortigern-77",
        "quixotic-tag",
    ];

    #[gpui::test]
    fn diagnostics_has_every_key_and_no_vault_content(cx: &mut TestAppContext) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Diagnostique Secret.vault");
        let mut vault = SyncedVault::create(
            &path,
            &SecretString::new("pw".into()),
            KdfParams::for_tests(),
            Uuid::new_v4(),
            Arc::new(NoopHooks),
        )
        .unwrap();
        let device = vault.device_id();
        let t = text::now_millis();
        let vault_id = vault.locked_summary().vault_id;
        vault
            .edit(|v| {
                let mut a = Item::new(SECRETS[0], device, t);
                a.tags.push(SECRETS[5].into());
                a.fields.push(Field::new(
                    "username",
                    FieldKind::Email,
                    SecretString::new(SECRETS[3].into()),
                    t,
                ));
                a.fields.push(Field::new(
                    "password",
                    FieldKind::Password,
                    SecretString::new(SECRETS[4].into()),
                    t,
                ));
                v.insert(a, t);
                v.insert(Item::new(SECRETS[1], device, t), t);
                let gone = v.insert(Item::new(SECRETS[2], device, t), t);
                v.delete(gone, t + 1).unwrap();
            })
            .unwrap();
        vault.save().unwrap();
        vault.backup_now().unwrap();
        let backups = vault.backups().unwrap().len();

        let app_device = Uuid::new_v4();
        let state = cx.new(|_| AppState::new(app_device, Vec::new(), false));
        let before = SystemTime::now();
        let (text, now, event_at) = state.update(cx, |s, cx| {
            s.install_unlocked_for_tests(vault);
            s.refresh_backups();
            s.vault_path = Some(path.clone());
            // A synthetic event records its label and arrival time.
            s.handle_sync_event(vault_sync::SyncEvent::ForeignVault, cx);
            let (label, at) = s.sync.last_event.expect("event recorded");
            assert_eq!(label, "foreign vault ignored");
            assert!(at >= before && at <= SystemTime::now());
            let now = at + Duration::from_secs(300);
            s.sync.last_saved = Some(now - Duration::from_secs(120));
            let host = Host {
                macos_version: Some("15.1.1".into()),
                model: Some("Mac15,6".into()),
                location: Some(SyncLocation::Provider("Dropbox".into())),
            };
            (diagnostics_text(s, now, &host), now, at)
        });

        assert_eq!(keys(&text), expected(false), "{text}");
        for line in [
            "format version: 2",
            "macOS version: 15.1.1",
            "Mac model: Mac15,6",
            "location: Dropbox",
            "items: 2",
            "trashed: 1",
            "Touch ID slot: no",
            "passkey slot: no",
            "Show Vault in Dock: yes",
            "appearance: Follow system",
            "text size: Default",
        ] {
            assert!(text.lines().any(|l| l == line), "{line:?} in\n{text}");
        }
        assert!(text.contains(&format!("\nbackups: {backups}\n")), "{text}");
        assert!(text.contains("last save: ") && text.contains("(2m ago), result: ok"));
        let event_line = format!(
            "last sync event: foreign vault ignored, {} (5m ago)",
            text::date_time(event_at)
        );
        assert!(
            text.lines().any(|l| l == event_line),
            "{event_line:?} in\n{text}"
        );

        let mut forbidden: Vec<String> = SECRETS.iter().map(|s| s.to_string()).collect();
        forbidden.extend([
            app_device.to_string(),
            device.to_string(),
            vault_id.to_string(),
            "Diagnostique".into(),
        ]);
        forbidden.extend(
            path.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .filter(|c| c.len() >= 4),
        );
        let assert_clean = |text: &str| {
            let lower = text.to_lowercase();
            for bad in &forbidden {
                assert!(
                    !lower.contains(&bad.to_lowercase()),
                    "{bad:?} leaked:\n{text}"
                );
            }
        };
        assert_clean(&text);

        // A measured unlock time adds its line right after KDF; another provider never
        // prints its raw name.
        let text = state.update(cx, |s, _| {
            let k = s.current_kdf().unwrap();
            s.security.kdf_timing = Some((
                (k.m_cost_kib, k.t_cost, k.p_cost),
                Duration::from_millis(612),
            ));
            let host = Host {
                location: Some(SyncLocation::Provider("AcmeSecretCorp".into())),
                ..Host::default()
            };
            diagnostics_text(s, now, &host)
        });
        assert_eq!(keys(&text), expected(true), "{text}");
        assert!(text.contains("unlock time: 0.61 s"));
        assert!(text.contains("location: other cloud"));
        assert!(!text.contains("AcmeSecretCorp"));

        // Error states whose texts carry the vault path and a title print fixed words only.
        let leaky = format!("{} failed for {}", path.display(), SECRETS[0]);
        let text = state.update(cx, |s, cx| {
            s.sync.backups_error = Some(leaky.clone().into());
            s.handle_sync_event(vault_sync::SyncEvent::Error(leaky.clone()), cx);
            s.sync_status = SyncStatus::Error(leaky.clone().into());
            s.sync.save_failing = true;
            s.sync.save_blocked = Some(super::super::sync::SaveBlockedNotice {
                message: leaky.clone().into(),
                offers_trash: false,
            });
            diagnostics_text(s, now, &Host::default())
        });
        assert_eq!(keys(&text), expected(true), "{text}");
        assert!(text.contains("\nbackups: unavailable\n"), "{text}");
        assert!(text.contains(", result: last attempt failed\n"), "{text}");
        assert!(text.contains("\nlast sync event: error, "), "{text}");
        assert_clean(&text);
    }

    #[gpui::test]
    fn diagnostics_without_a_vault_is_a_full_block(cx: &mut TestAppContext) {
        let state = cx.new(|_| AppState::new(Uuid::new_v4(), Vec::new(), false));
        let text = state.read_with(cx, |s, _| {
            diagnostics_text(s, SystemTime::now(), &Host::default())
        });
        assert_eq!(keys(&text), expected(false), "{text}");
        assert!(text.contains("format version: no vault open"));
        assert!(text.contains("location: no vault open"));
        assert!(text.contains(&format!("app version: {}", env!("CARGO_PKG_VERSION"))));
        assert!(text.contains("last save: none this session, result: n/a"));
        assert!(text.contains("last sync event: none this session"));
        assert!(text.contains("macOS version: unknown\nMac model: unknown\n"));
    }
}
