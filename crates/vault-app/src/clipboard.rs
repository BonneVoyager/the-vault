//! Clipboard with auto-clear (specs/05-ui.md §2.3, §3; specs/04-macos.md §3).
//!
//! [`copy_secret`] is the only place a secret reaches the system pasteboard. It writes
//! through vault-macos with `org.nspasteboard.ConcealedType`, so clipboard managers skip
//! the entry. [`Clipboard`] remembers the pasteboard's change count right after our write
//! and later clears only if that count is unchanged, so a value the user copied from
//! another app is never wiped.

use vault_core::SecretString;
use vault_macos::ChangeCount;

/// Writes `text` to the system pasteboard as a concealed entry. `None` if AppKit refused it.
#[cfg_attr(test, allow(dead_code))]
pub fn copy_secret(text: &SecretString) -> Option<ChangeCount> {
    vault_macos::Clipboard::write_concealed(text)
}

/// The pasteboard, abstracted so tests can observe and simulate other writers.
pub trait Pasteboard {
    /// Writes `text` and returns the change count right after the write, or `None` if
    /// the write failed.
    fn write_concealed(&self, text: &SecretString) -> Option<ChangeCount>;
    /// Clears the pasteboard only if its change count is still `cc`.
    fn clear_if_unchanged(&self, cc: ChangeCount);
}

/// The real macOS pasteboard via vault-macos. Tests use the fake.
#[cfg_attr(test, allow(dead_code))]
pub struct SystemPasteboard;

impl Pasteboard for SystemPasteboard {
    fn write_concealed(&self, text: &SecretString) -> Option<ChangeCount> {
        copy_secret(text)
    }

    fn clear_if_unchanged(&self, cc: ChangeCount) {
        vault_macos::Clipboard::clear_if_unchanged(cc);
    }
}

pub struct Clipboard {
    board: Box<dyn Pasteboard>,
    /// Change count after our last write, until it is cleared.
    ours: Option<ChangeCount>,
    /// Bumped on every copy, so a stale clear timer never clears a newer copy early.
    generation: u64,
}

impl Clipboard {
    pub fn new(board: Box<dyn Pasteboard>) -> Self {
        Self {
            board,
            ours: None,
            generation: 0,
        }
    }

    /// Writes `text` and returns the generation to pass to [`Self::expire`], or `None`
    /// if the pasteboard refused the write.
    pub fn copy(&mut self, text: &SecretString) -> Option<u64> {
        self.generation = self.generation.wrapping_add(1);
        self.ours = self.board.write_concealed(text);
        self.ours.map(|_| self.generation)
    }

    /// Clear timer fired: clears only if no newer copy happened since `generation`.
    pub fn expire(&mut self, generation: u64) {
        if generation == self.generation {
            self.clear_if_ours();
        }
    }

    /// Clears the pasteboard if nobody wrote to it since our copy. Called on lock.
    pub fn clear_if_ours(&mut self) {
        if let Some(cc) = self.ours.take() {
            self.board.clear_if_unchanged(cc);
        }
    }
}

#[cfg(test)]
pub mod fake {
    //! In-memory pasteboard with a change count, for tests.

    use std::cell::RefCell;
    use std::rc::Rc;

    use vault_core::ExposeSecret as _;

    use super::*;

    #[derive(Default)]
    pub struct Inner {
        pub text: Option<String>,
        pub change_count: i64,
        /// Every `clear_if_unchanged` argument, in order.
        pub clear_calls: Vec<ChangeCount>,
    }

    #[derive(Clone, Default)]
    pub struct FakePasteboard(pub Rc<RefCell<Inner>>);

    impl FakePasteboard {
        pub fn contents(&self) -> Option<String> {
            self.0.borrow().text.clone()
        }

        pub fn change_count(&self) -> ChangeCount {
            ChangeCount(self.0.borrow().change_count)
        }

        pub fn clear_calls(&self) -> Vec<ChangeCount> {
            self.0.borrow().clear_calls.clone()
        }

        /// Another app writes to the pasteboard.
        pub fn set(&self, text: &str) {
            let mut p = self.0.borrow_mut();
            p.change_count += 1;
            p.text = Some(text.to_owned());
        }
    }

    impl Pasteboard for FakePasteboard {
        fn write_concealed(&self, text: &SecretString) -> Option<ChangeCount> {
            let mut p = self.0.borrow_mut();
            p.change_count += 1;
            p.text = Some(text.expose_secret().to_string());
            Some(ChangeCount(p.change_count))
        }

        fn clear_if_unchanged(&self, cc: ChangeCount) {
            let mut p = self.0.borrow_mut();
            p.clear_calls.push(cc);
            if p.change_count == cc.0 {
                p.change_count += 1;
                p.text = None;
            }
        }
    }
}
