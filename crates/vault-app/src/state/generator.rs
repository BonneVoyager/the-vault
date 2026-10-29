//! Password generator state (specs/05-ui.md §2.4): the spec behind the popover's controls,
//! the current preview, and where a "Use" would put it.

use std::ops::RangeInclusive;

use gpui::Context;
use vault_core::{FieldKind, PassphraseSpec, PasswordSpec, SecretString, passphrase, password};

use super::{AppState, Mode};

pub const LENGTH_RANGE: RangeInclusive<usize> = 8..=64;
pub const WORDS_RANGE: RangeInclusive<usize> = 3..=8;
/// Separators offered in the passphrase tab.
pub const SEPARATORS: [char; 5] = ['-', '.', '_', ' ', ','];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GenTab {
    #[default]
    Password,
    Passphrase,
}

/// Where the open generator popover is anchored and what "Use" fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorTarget {
    /// ⌘G: anchored in the item list header, no "Use".
    Global,
    /// The "Generate" button of the edit-buffer row with this key.
    Field(u64),
}

/// A password-class toggle in the Password tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharClass {
    Lower,
    Upper,
    Digits,
    Symbols,
    ExcludeAmbiguous,
}

pub struct Generator {
    pub tab: GenTab,
    pub password: PasswordSpec,
    pub passphrase: PassphraseSpec,
    preview: SecretString,
}

impl Default for Generator {
    fn default() -> Self {
        let mut g = Self {
            tab: GenTab::default(),
            password: PasswordSpec::default(),
            passphrase: PassphraseSpec::default(),
            preview: SecretString::new(String::new()),
        };
        g.regenerate();
        g
    }
}

impl Generator {
    pub fn preview(&self) -> &SecretString {
        &self.preview
    }

    pub fn regenerate(&mut self) {
        self.preview = match self.tab {
            GenTab::Password => password(&self.password),
            GenTab::Passphrase => passphrase(&self.passphrase),
        };
    }

    pub fn set_tab(&mut self, tab: GenTab) {
        if self.tab != tab {
            self.tab = tab;
            self.regenerate();
        }
    }

    pub fn set_length(&mut self, length: usize) {
        let length = length.clamp(*LENGTH_RANGE.start(), *LENGTH_RANGE.end());
        if self.password.length != length {
            self.password.length = length;
            self.regenerate();
        }
    }

    /// Flips a class. The last enabled character class cannot be turned off.
    pub fn toggle(&mut self, class: CharClass) {
        let p = &mut self.password;
        let enabled = [p.lower, p.upper, p.digits, p.symbols]
            .iter()
            .filter(|b| **b)
            .count();
        let flag = match class {
            CharClass::Lower => &mut p.lower,
            CharClass::Upper => &mut p.upper,
            CharClass::Digits => &mut p.digits,
            CharClass::Symbols => &mut p.symbols,
            CharClass::ExcludeAmbiguous => &mut p.exclude_ambiguous,
        };
        if *flag && enabled == 1 && class != CharClass::ExcludeAmbiguous {
            return;
        }
        *flag = !*flag;
        self.regenerate();
    }

    pub fn set_words(&mut self, words: usize) {
        let words = words.clamp(*WORDS_RANGE.start(), *WORDS_RANGE.end());
        if self.passphrase.words != words {
            self.passphrase.words = words;
            self.regenerate();
        }
    }

    pub fn set_separator(&mut self, separator: char) {
        self.passphrase.separator = separator;
        self.regenerate();
    }

    pub fn toggle_capitalize(&mut self) {
        self.passphrase.capitalize = !self.passphrase.capitalize;
        self.regenerate();
    }

    pub fn toggle_number(&mut self) {
        self.passphrase.number = !self.passphrase.number;
        self.regenerate();
    }
}

impl AppState {
    /// ⌘G (Global) or a password row's Generate button (Field).
    pub fn open_generator(&mut self, target: GeneratorTarget, cx: &mut Context<Self>) {
        if !self.main_active() {
            return;
        }
        // A field target must be a password row of the current edit buffer.
        if let GeneratorTarget::Field(key) = target {
            let ok = self
                .edit_buffer()
                .and_then(|b| b.field(key))
                .is_some_and(|f| f.kind == FieldKind::Password);
            if !ok {
                return;
            }
        }
        self.generator.regenerate();
        self.generator_target = Some(target);
        cx.notify();
    }

    pub fn close_generator(&mut self, cx: &mut Context<Self>) {
        if self.generator_target.take().is_some() {
            cx.notify();
        }
    }

    /// Mutates the generator spec from the popover's controls.
    pub fn update_generator(&mut self, cx: &mut Context<Self>, f: impl FnOnce(&mut Generator)) {
        f(&mut self.generator);
        cx.notify();
    }

    /// Copy in the popover: the preview goes through the same auto-clearing copy path.
    pub fn copy_generated(&mut self, cx: &mut Context<Self>) {
        if self.main_active() {
            let value = self.generator.preview().clone();
            self.copy_secret(value, cx);
        }
    }

    /// "Use": writes the preview into the target field and closes the popover.
    pub fn use_generated(&mut self, cx: &mut Context<Self>) {
        let Some(GeneratorTarget::Field(key)) = self.generator_target else {
            return;
        };
        let value = self.generator.preview().clone();
        if let Mode::Edit(b) | Mode::New(_, b) = &mut self.mode
            && let Some(i) = b.index(key)
        {
            b.item.fields[i].value = value;
            b.pushed.push(key);
        }
        self.generator_target = None;
        cx.notify();
    }
}

#[cfg(test)]
mod tests {
    use vault_core::ExposeSecret as _;

    use super::*;

    #[test]
    fn spec_follows_the_controls() {
        let mut g = Generator::default();
        g.set_length(3);
        assert_eq!(g.password.length, 8, "clamped to the slider range");
        g.set_length(100);
        assert_eq!(g.password.length, 64);
        g.set_length(16);
        g.toggle(CharClass::Symbols);
        g.toggle(CharClass::Upper);
        assert_eq!(
            g.password,
            PasswordSpec {
                length: 16,
                lower: true,
                upper: false,
                digits: true,
                symbols: false,
                exclude_ambiguous: true,
            }
        );
        let preview = g.preview().expose_secret().to_owned();
        assert_eq!(preview.chars().count(), 16);
        assert!(
            preview
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );

        // The last class cannot be switched off.
        g.toggle(CharClass::Digits);
        g.toggle(CharClass::Lower);
        assert!(g.password.lower);

        g.set_tab(GenTab::Passphrase);
        g.set_words(2);
        assert_eq!(g.passphrase.words, 3);
        g.set_separator('.');
        g.toggle_number();
        g.toggle_capitalize();
        assert_eq!(
            g.passphrase,
            PassphraseSpec {
                words: 3,
                separator: '.',
                capitalize: false,
                number: false,
            }
        );
        let phrase = g.preview().expose_secret().to_owned();
        assert_eq!(phrase.split('.').count(), 3);
        assert!(
            phrase
                .chars()
                .all(|c| c == '.' || c == '-' || c.is_ascii_lowercase())
        );
    }
}
