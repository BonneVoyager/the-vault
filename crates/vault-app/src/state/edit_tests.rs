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
            let mut gh = Item::new("GitHub", device, 10);
            gh.fields = vec![
                Field::new("username", FieldKind::Text, secret("chris"), 10),
                Field::new("password", FieldKind::Password, secret("old"), 10),
            ];
            let note = Item::new("Alarm", device, 10);
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
        s.begin_new(crate::templates::Template::Login, "Draft".into(), cx);
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
        s.set_filter(Filter::Tag("note".into()), cx);
        s.begin_new(crate::templates::Template::Card, "Visa".into(), cx);
        let b = s.edit_buffer().unwrap();
        let names: Vec<_> = b.item.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["number", "expiry", "cvv", "name"]);
        assert_eq!(b.item.fields[1].kind, FieldKind::MonthYear);
        s.save_edit(cx);
        assert!(!s.is_editing());
        let item = s.selected_item().expect("new item selected");
        assert_eq!(item.title, "Visa");
        assert_eq!(item.tags, ["card"]);
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
        s.begin_new(crate::templates::Template::Login, String::new(), cx);
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
        s.begin_new(crate::templates::Template::Note, "Tagged".into(), cx);
        s.edit(cx, |b| {
            b.add_tag("home");
        });
        s.save_edit(cx);
        assert_eq!(s.selected_item().unwrap().tags, ["note", "home"]);

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
    let mut item = Item::new("My Bank: ü", Uuid::new_v4(), 1);
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

#[test]
fn kind_labels_are_capitalised_and_number_is_not_offered() {
    let labels: Vec<_> = ADDABLE_KINDS.into_iter().map(kind_name).collect();
    assert_eq!(
        labels,
        [
            "Text",
            "Password",
            "One-time code",
            "URL",
            "Notes",
            "Email",
            "Date",
            "Month/year"
        ]
    );
    // `number` was removed: it parses as an unknown kind, which is never offered.
    assert_eq!(FieldKind::parse("number"), None);
    assert!(!ADDABLE_KINDS.contains(&FieldKind::Other));
    assert_eq!(ADDABLE_KINDS, FieldKind::ALL);

    let mut b = EditBuffer::new(Item::new("x", Uuid::new_v4(), 1));
    let k1 = b.add_field(FieldKind::Totp);
    let k2 = b.add_field(FieldKind::Totp);
    let k3 = b.add_field(FieldKind::Url);
    assert_eq!(b.field(k1).unwrap().name, "one-time code");
    assert_eq!(b.field(k2).unwrap().name, "one-time code 2");
    assert_eq!(b.field(k3).unwrap().name, "url");
}

/// Gives GitHub's password two history entries ("old" at 20, "mid" at 30).
fn with_history(state: &Entity<AppState>, gh: Uuid, cx: &mut TestAppContext) {
    state.update(cx, |s, cx| {
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| {
                v.set_field(gh, "password", secret("mid"), 20)?;
                v.set_field(gh, "password", secret("new"), 30)
            })
            .unwrap()
            .unwrap();
        s.vault_changed();
        s.select(gh, cx);
    });
}

fn stamps(item: &Item) -> Vec<Millis> {
    item.history.iter().map(|h| h.replaced_at).collect()
}

#[gpui::test]
fn removed_history_entry_is_gone_after_save(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, gh, _) = setup(dir.path(), cx);
    with_history(&state, gh, cx);
    state.update(cx, |s, cx| {
        let before = stored(s, gh);
        assert_eq!(before.history.len(), 2);
        let gone = before.history[0].replaced_at;
        let kept = before.history[1].replaced_at;
        s.begin_edit(cx);
        s.edit(cx, |b| b.remove_history(gone));
        let b = s.edit_buffer().unwrap();
        assert!(b.has_changes(), "a pending removal is a change");
        assert_eq!(b.history().count(), 1);
        assert_eq!(b.item.history.len(), 2, "nothing removed before Save");
        assert_eq!(stored(s, gh).history.len(), 2);
        s.save_edit(cx);
        assert!(!s.is_editing());
        let after = stored(s, gh);
        assert_eq!(stamps(&after), vec![kept]);
        assert!(after.removed_history.contains(&gone));
        assert_eq!(
            after.field("password").unwrap().value.expose_secret(),
            "new"
        );
    });
}

#[gpui::test]
fn cancel_discards_history_removals(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, gh, _) = setup(dir.path(), cx);
    with_history(&state, gh, cx);
    state.update(cx, |s, cx| {
        let before = stamps(&stored(s, gh));
        s.begin_edit(cx);
        s.edit(cx, |b| b.clear_history());
        s.cancel_edit(cx);
        assert!(!s.is_editing());
        let after = stored(s, gh);
        assert_eq!(stamps(&after), before);
        assert!(after.removed_history.is_empty());
        // A fresh edit starts with nothing pending.
        s.begin_edit(cx);
        let b = s.edit_buffer().unwrap();
        assert!(b.removed_history.is_empty());
        assert!(!b.has_changes());
    });
}

#[gpui::test]
fn clear_history_empties_it_on_save(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, gh, _) = setup(dir.path(), cx);
    with_history(&state, gh, cx);
    state.update(cx, |s, cx| {
        let before = stamps(&stored(s, gh));
        s.begin_edit(cx);
        s.edit(cx, |b| b.clear_history());
        assert_eq!(s.edit_buffer().unwrap().history().count(), 0);
        s.save_edit(cx);
        let after = stored(s, gh);
        assert!(after.history.is_empty());
        for stamp in before {
            assert!(after.removed_history.contains(&stamp));
        }
    });
}

#[gpui::test]
fn guard_prompts_when_only_a_history_removal_is_pending(cx: &mut TestAppContext) {
    let dir = tempfile::tempdir().unwrap();
    let (state, gh, note) = setup(dir.path(), cx);
    with_history(&state, gh, cx);
    state.update(cx, |s, cx| {
        let stamp = stored(s, gh).history[0].replaced_at;
        s.begin_edit(cx);
        s.edit(cx, |b| b.remove_history(stamp));
        s.select(note, cx);
        assert_eq!(s.discard_prompt, Some(Navigation::Select(note)));
        assert!(s.is_editing());
        assert_eq!(s.selection, Some(gh));
        // Discard drops the removal.
        s.discard_changes(cx);
        assert_eq!(s.selection, Some(note));
        assert_eq!(stored(s, gh).history.len(), 2);
    });
}

#[gpui::test]
fn icon_picker_choices_are_part_of_the_edit(cx: &mut TestAppContext) {
    use crate::icon::{IconSpec, Move, PALETTE, PickerCell, SYMBOLS, resolve};
    let dir = tempfile::tempdir().unwrap();
    let (state, gh, _) = setup(dir.path(), cx);
    state.update(cx, |s, cx| {
        s.select(gh, cx);
        s.begin_edit(cx);
        // Opening the picker starts on "Automatic" and is not a change.
        s.set_icon_picker(true, cx);
        let b = s.edit_buffer().unwrap();
        assert_eq!(b.icon_picker.unwrap().cell(), PickerCell::Automatic);
        assert!(!b.has_changes());

        // Keyboard: down to the first symbol, right once, Enter.
        s.icon_picker_move(Move::Down, cx);
        s.icon_picker_move(Move::Right, cx);
        s.icon_picker_choose(cx);
        let b = s.edit_buffer().unwrap();
        let icon = b.item.icon.clone().unwrap();
        assert_eq!(
            (icon.kind.as_str(), icon.value.as_str()),
            ("symbol", SYMBOLS[1].0)
        );
        assert!(b.has_changes());

        // A colour recolours the symbol.
        s.choose_icon(PickerCell::Color(1), cx);
        let item = s.edit_buffer().unwrap().item.clone();
        assert_eq!(
            resolve(&item),
            IconSpec::Symbol {
                name: SYMBOLS[1].1,
                color: PALETTE[1]
            }
        );
        s.save_edit(cx);
        let saved = stored(s, gh).icon.unwrap();
        assert_eq!(saved.kind, "symbol");
        assert_eq!(saved.color.as_deref(), Some("#30A46C"));

        // Back to automatic clears the icon; saved too.
        s.begin_edit(cx);
        assert_eq!(
            s.edit_buffer().unwrap().icon_picker,
            None,
            "a new edit starts closed"
        );
        s.choose_icon(PickerCell::Automatic, cx);
        s.save_edit(cx);
        assert_eq!(stored(s, gh).icon, None);

        // Colour only on an automatic icon: a tinted letter. Cancel discards it.
        s.begin_edit(cx);
        s.choose_icon(PickerCell::Color(2), cx);
        let icon = s.edit_buffer().unwrap().item.icon.clone().unwrap();
        assert_eq!(
            (icon.kind.as_str(), icon.color.as_deref()),
            ("letter", Some("#E5484D"))
        );
        s.cancel_edit(cx);
        assert_eq!(stored(s, gh).icon, None);
    });
}

#[gpui::test]
fn icon_change_keeps_fields_and_unknown_icons_survive_other_edits(cx: &mut TestAppContext) {
    use crate::icon::PickerCell;
    let dir = tempfile::tempdir().unwrap();
    let (state, gh, _) = setup(dir.path(), cx);
    state.update(cx, |s, cx| {
        // A newer app's image icon, set behind the editor's back.
        let mut image = vault_core::ItemIcon::new("image", "att-1");
        image.color = Some("#123456".into());
        let set = image.clone();
        s.vault
            .as_mut()
            .unwrap()
            .edit(|v| v.update(gh, 20, move |it| it.icon = Some(set)))
            .unwrap()
            .unwrap();
        s.select(gh, cx);
        let before = stored(s, gh);
        // A title edit leaves the unknown icon untouched.
        s.begin_edit(cx);
        s.set_edit_title("GitHub 2".into(), cx);
        s.save_edit(cx);
        assert_eq!(stored(s, gh).icon, Some(image));
        // An icon-only edit keeps every field stamp.
        s.begin_edit(cx);
        s.choose_icon(PickerCell::Symbol(0), cx);
        s.save_edit(cx);
        let after = stored(s, gh);
        assert_eq!(after.icon.unwrap().kind, "symbol");
        for (a, b) in after.fields.iter().zip(&before.fields) {
            assert_eq!(a.modified_at, b.modified_at);
        }
    });
}
