//! `vault edit`: parsing of the flags and one atomic application to an item.
//!
//! Values given on the command line are a dev-tool convenience and are visible in process
//! listings; secrets should come through `--set-env`.

use anyhow::{Result, anyhow, bail};
use vault_core::{Field, FieldKind, Item, ItemIcon, SecretString, UnlockedVault, Uuid};

use crate::sanitize_for_terminal;

/// How `--set` names its target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldRef {
    Id(Uuid),
    Name(String),
}

pub struct NewField {
    pub kind: FieldKind,
    pub name: String,
    pub value: SecretString,
}

#[derive(Default)]
pub struct EditPlan {
    pub title: Option<String>,
    pub favorite: Option<bool>,
    pub tags_add: Vec<String>,
    pub tags_rm: Vec<String>,
    /// `Some(None)` is `--icon auto`.
    pub icon: Option<Option<ItemIcon>>,
    pub sets: Vec<(FieldRef, SecretString)>,
    pub adds: Vec<NewField>,
    pub rm_fields: Vec<Uuid>,
}

impl EditPlan {
    pub fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.favorite.is_none()
            && self.tags_add.is_empty()
            && self.tags_rm.is_empty()
            && self.icon.is_none()
            && self.sets.is_empty()
            && self.adds.is_empty()
            && self.rm_fields.is_empty()
    }
}

fn valid_color(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// `auto` | `symbol:<IconName>[:#RRGGBB]` | `letter:#RRGGBB`.
pub fn parse_icon(s: &str) -> Result<Option<ItemIcon>> {
    if s == "auto" {
        return Ok(None);
    }
    let parts: Vec<&str> = s.split(':').collect();
    match parts.as_slice() {
        ["symbol", name] | ["symbol", name, _] if !name.is_empty() => {
            let mut icon = ItemIcon::new("symbol", *name);
            if let [_, _, c] = parts.as_slice() {
                if !valid_color(c) {
                    bail!("icon colour must be #RRGGBB");
                }
                icon.color = Some((*c).to_owned());
            }
            Ok(Some(icon))
        }
        ["letter", c] if valid_color(c) => {
            let mut icon = ItemIcon::new("letter", "");
            icon.color = Some((*c).to_owned());
            Ok(Some(icon))
        }
        _ => bail!("icon must be auto, symbol:<IconName>[:#RRGGBB] or letter:#RRGGBB"),
    }
}

/// `<field>=<value>` where `<field>` is an id UUID or a name.
pub fn parse_target(s: &str) -> Result<(FieldRef, String)> {
    let (key, value) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("expected <field>=<value>"))?;
    Ok((parse_field_ref(key)?, value.to_owned()))
}

pub fn parse_field_ref(key: &str) -> Result<FieldRef> {
    if key.is_empty() {
        bail!("field name or id must not be empty");
    }
    Ok(match key.parse::<Uuid>() {
        Ok(id) => FieldRef::Id(id),
        Err(_) => FieldRef::Name(key.to_owned()),
    })
}

/// `<kind>:<name>[=<value>]`; kinds text, password, url, notes, email, section.
pub fn parse_add(s: &str) -> Result<NewField> {
    let (kind, rest) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("expected <kind>:<name>[=<value>]"))?;
    let kind = match kind {
        "text" => FieldKind::Text,
        "password" => FieldKind::Password,
        "url" => FieldKind::Url,
        "notes" => FieldKind::Notes,
        "email" => FieldKind::Email,
        "section" => FieldKind::Section,
        other => bail!(
            "unknown field kind \"{}\" (text, password, url, notes, email, section)",
            sanitize_for_terminal(other)
        ),
    };
    let (name, value) = rest.split_once('=').unwrap_or((rest, ""));
    let value = if kind == FieldKind::Section {
        String::new()
    } else {
        value.to_owned()
    };
    Ok(NewField {
        kind,
        name: name.to_owned(),
        value: SecretString::new(value),
    })
}

fn name_matches<'a>(item: &'a Item, name: &'a str) -> impl Iterator<Item = &'a Field> {
    item.fields
        .iter()
        .filter(move |f| f.kind != FieldKind::Section && f.name.eq_ignore_ascii_case(name))
}

fn ambiguous(name: &str, n: usize) -> anyhow::Error {
    anyhow!(
        "ambiguous: {n} fields named \"{}\"; use the field id instead (`vault get --ids`): --set <id>=<value>",
        sanitize_for_terminal(name)
    )
}

/// Check the whole plan against the item without changing anything.
fn validate(item: &Item, plan: &EditPlan) -> Result<()> {
    let mut created: Vec<&str> = Vec::new();
    for (target, _) in &plan.sets {
        match target {
            FieldRef::Id(id) => {
                let f = item
                    .fields
                    .iter()
                    .find(|f| f.id == *id)
                    .ok_or_else(|| anyhow!("no field with id {id}"))?;
                if f.kind == FieldKind::Section {
                    bail!("field {id} is a section heading and takes no value");
                }
            }
            FieldRef::Name(name) => {
                let n = name_matches(item, name).count()
                    + created
                        .iter()
                        .filter(|c| c.eq_ignore_ascii_case(name))
                        .count();
                if n > 1 {
                    return Err(ambiguous(name, n));
                }
                if n == 0 {
                    created.push(name);
                }
            }
        }
    }
    for id in &plan.rm_fields {
        if !item.fields.iter().any(|f| f.id == *id) {
            bail!("no field with id {id}");
        }
    }
    Ok(())
}

/// Apply `plan` to `item` inside one edit: validated first so a failure changes nothing.
pub fn apply(v: &mut UnlockedVault, item_id: Uuid, plan: &EditPlan, now: u64) -> Result<()> {
    let item = v
        .get(item_id)
        .filter(|i| !i.is_deleted())
        .ok_or_else(|| anyhow!("no such item"))?;
    validate(item, plan)?;
    for (target, value) in &plan.sets {
        let value = value.clone();
        let item = v.get(item_id).ok_or_else(|| anyhow!("item vanished"))?;
        match target {
            FieldRef::Id(id) => v.set_field(item_id, *id, value, now)?,
            FieldRef::Name(name) => {
                if name_matches(item, name).next().is_some() {
                    v.set_field_named(item_id, name, value, now)?;
                } else {
                    let f = Field::new(name.clone(), FieldKind::Text, value, now);
                    v.update(item_id, now, |it| it.fields.push(f))?;
                }
            }
        }
    }
    let meta = plan.title.is_some()
        || plan.favorite.is_some()
        || !plan.tags_add.is_empty()
        || !plan.tags_rm.is_empty()
        || plan.icon.is_some()
        || !plan.adds.is_empty();
    if meta {
        v.update(item_id, now, |it| {
            if let Some(t) = &plan.title {
                it.title.clone_from(t);
            }
            if let Some(f) = plan.favorite {
                it.favorite = f;
            }
            for t in &plan.tags_rm {
                it.tags.retain(|x| !x.eq_ignore_ascii_case(t));
            }
            for t in &plan.tags_add {
                if !it.tags.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                    it.tags.push(t.clone());
                }
            }
            if let Some(icon) = &plan.icon {
                it.icon.clone_from(icon);
            }
            for a in &plan.adds {
                let value = a.value.clone();
                it.fields
                    .push(Field::new(a.name.clone(), a.kind, value, now));
            }
        })?;
    }
    for id in &plan.rm_fields {
        v.remove_field(item_id, *id, now)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{ExposeSecret, KdfParams};

    fn vault_with(fields: &[(&str, FieldKind)]) -> (UnlockedVault, Uuid) {
        let mut v = UnlockedVault::create(
            &SecretString::new("pw".to_owned()),
            KdfParams::for_tests(),
            Uuid::nil(),
        );
        let mut i = Item::new("t", Uuid::nil(), 1);
        for (n, k) in fields {
            i.fields
                .push(Field::new(*n, *k, SecretString::new("old".to_owned()), 1));
        }
        let id = v.insert(i, 1);
        (v, id)
    }

    #[test]
    fn icon_forms() {
        assert_eq!(parse_icon("auto").unwrap(), None);
        let s = parse_icon("symbol:key:#A1b2C3").unwrap().unwrap();
        assert_eq!((s.kind.as_str(), s.value.as_str()), ("symbol", "key"));
        assert_eq!(s.color.as_deref(), Some("#A1b2C3"));
        let l = parse_icon("letter:#000000").unwrap().unwrap();
        assert_eq!((l.kind.as_str(), l.value.as_str()), ("letter", ""));
        for bad in [
            "",
            "symbol",
            "symbol:",
            "symbol:k:red",
            "letter",
            "letter:red",
            "logo:x",
        ] {
            assert!(parse_icon(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn add_parsing() {
        let a = parse_add("section:Work=ignored").unwrap();
        assert_eq!(a.kind, FieldKind::Section);
        assert_eq!(a.value.expose_secret(), "");
        let a = parse_add("password:pin").unwrap();
        assert_eq!((a.kind, a.name.as_str()), (FieldKind::Password, "pin"));
        let a = parse_add("url:site=https://x?a=b").unwrap();
        assert_eq!(a.value.expose_secret(), "https://x?a=b");
        assert!(parse_add("totp:x").is_err());
        assert!(parse_add("nokind").is_err());
    }

    #[test]
    fn set_by_name_id_and_new_name() {
        let (mut v, id) = vault_with(&[("user", FieldKind::Text)]);
        let fid = v.get(id).unwrap().fields[0].id;
        let plan = EditPlan {
            sets: vec![
                (FieldRef::Name("USER".into()), SecretString::new("a".into())),
                (
                    FieldRef::Name("fresh".into()),
                    SecretString::new("b".into()),
                ),
            ],
            ..Default::default()
        };
        apply(&mut v, id, &plan, 10).unwrap();
        let it = v.get(id).unwrap();
        assert_eq!(it.fields[0].value.expose_secret(), "a");
        assert_eq!(it.fields[1].name, "fresh");
        assert_eq!(it.fields[1].kind, FieldKind::Text);
        let plan = EditPlan {
            sets: vec![(FieldRef::Id(fid), SecretString::new("c".into()))],
            ..Default::default()
        };
        apply(&mut v, id, &plan, 20).unwrap();
        assert_eq!(v.get(id).unwrap().fields[0].value.expose_secret(), "c");
    }

    #[test]
    fn ambiguity_changes_nothing_and_id_works() {
        let (mut v, id) = vault_with(&[("dup", FieldKind::Text), ("dup", FieldKind::Text)]);
        let plan = EditPlan {
            title: Some("new".into()),
            sets: vec![(FieldRef::Name("dup".into()), SecretString::new("x".into()))],
            ..Default::default()
        };
        let e = apply(&mut v, id, &plan, 10).unwrap_err().to_string();
        assert!(
            e.contains("ambiguous: 2 fields named \"dup\"") && e.contains("id"),
            "{e}"
        );
        assert_eq!(v.get(id).unwrap().title, "t");
        let second = v.get(id).unwrap().fields[1].id;
        let plan = EditPlan {
            sets: vec![(FieldRef::Id(second), SecretString::new("x".into()))],
            ..Default::default()
        };
        apply(&mut v, id, &plan, 20).unwrap();
        let it = v.get(id).unwrap();
        assert_eq!(it.fields[0].value.expose_secret(), "old");
        assert_eq!(it.fields[1].value.expose_secret(), "x");
    }

    #[test]
    fn meta_add_and_remove() {
        let (mut v, id) = vault_with(&[("gone", FieldKind::Text)]);
        v.update(id, 2, |it| it.tags.push("b".into())).unwrap();
        let gone = v.get(id).unwrap().fields[0].id;
        let plan = EditPlan {
            title: Some("Renamed".into()),
            favorite: Some(true),
            tags_add: vec!["a".into(), "A".into()],
            tags_rm: vec!["b".into()],
            icon: Some(parse_icon("letter:#112233").unwrap()),
            adds: vec![parse_add("section:Head").unwrap()],
            rm_fields: vec![gone],
            ..Default::default()
        };
        apply(&mut v, id, &plan, 10).unwrap();
        let it = v.get(id).unwrap();
        assert_eq!(it.title, "Renamed");
        assert!(it.favorite);
        assert_eq!(it.tags, ["a"]);
        assert!(it.icon.is_some());
        assert_eq!(it.fields.len(), 1);
        assert_eq!(it.fields[0].kind, FieldKind::Section);
        assert_eq!(it.fields[0].value.expose_secret(), "");
        assert!(it.removed_fields.iter().any(|t| t.id == gone));
        let plan = EditPlan {
            icon: Some(None),
            ..Default::default()
        };
        apply(&mut v, id, &plan, 20).unwrap();
        assert!(v.get(id).unwrap().icon.is_none());
        let plan = EditPlan {
            rm_fields: vec![gone],
            ..Default::default()
        };
        assert!(apply(&mut v, id, &plan, 30).is_err());
    }

    #[test]
    fn set_on_a_section_is_refused() {
        let (mut v, id) = vault_with(&[("Head", FieldKind::Section)]);
        let sid = v.get(id).unwrap().fields[0].id;
        let plan = EditPlan {
            sets: vec![(FieldRef::Id(sid), SecretString::new("x".into()))],
            ..Default::default()
        };
        let e = apply(&mut v, id, &plan, 10).unwrap_err().to_string();
        assert!(e.contains("is a section heading and takes no value"), "{e}");
        assert_eq!(v.get(id).unwrap().fields[0].value.expose_secret(), "old");
    }
}
