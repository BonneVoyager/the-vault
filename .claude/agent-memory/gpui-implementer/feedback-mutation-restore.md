---
name: feedback-mutation-restore
description: Mutation checks in files other agents also edit must use targeted replace and reverse replace, never copy a snapshot back over the file
metadata:
  type: feedback
---

When mutation-checking a test, change the code with a targeted string replace and undo it with the reverse replace. Never `cp` a backup snapshot back over a file another agent may be editing.

**Why:** on 2026-10-31, restoring `item_window.rs` from a 30-second-old snapshot could have silently erased the other implementer's concurrent edit. The lead had to be asked to check. Polling loops that wait for another agent's build to recover were also rejected by the user.

**How to apply:** any file outside my sole ownership, or any file the lead says someone else is editing. A snapshot copy is fine only for files no one else touches. See [[feedback-fmt-scope]].
