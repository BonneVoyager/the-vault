# Vault Help

Vault keeps your passwords in one encrypted file on this Mac. Nothing leaves the file unless you put the file in a synced folder yourself.

## Unlocking

Type your master password and press Return. If Touch ID is turned on in Settings ▸ Security, Vault asks for your fingerprint first; the password always works too. After a few minutes without activity Vault locks itself (Settings ▸ General ▸ Auto-lock).

## Items

Press ⌘N for a new item and pick a template. ⌘E edits the selected item, ⌘S saves, Esc cancels. Drag the handle on the left of a field to reorder fields while editing. Deleted items stay in Recently Deleted for 30 days.

## Copying secrets

⌘C on a selected row copies the username, ⌘⇧C the password, ⌘⇧T the current one-time code. The clipboard is cleared after the time set in Settings ▸ General. Hold ⌥ to reveal the masked values in the detail view while the key is down (the TOTP secret stays hidden).

## Sync between Macs

Put the vault package in a folder that iCloud Drive, Dropbox or any other service syncs, then open the same package on the other Mac. Vault merges changes from both sides; when two Macs change the same field, the later change wins and the older password is kept in that field's history. Backups live inside the package (Settings ▸ Sync & Backup): a copy of the vault is taken after changes, about once an hour; everything from the last day is kept, then one copy a day for 30 days, one a week for 12 weeks and one a month for 3 years. "Keep daily backups for" scales all of that from 15 to 120 days.

## Menu bar padlock

With "Show Vault in Dock" turned off, Vault lives in the menu bar instead. Click the padlock to open the window; right-click it to lock, unlock or quit. With "Launch at login" on, Vault starts there silently.

## Keyboard shortcuts

| Action | Keys |
|---|---|
| Search | ⌘F |
| New item | ⌘N |
| Edit / Save / Cancel | ⌘E / ⌘S / Esc |
| Copy username / password / one-time code | ⌘C / ⌘⇧C / ⌘⇧T |
| Reveal password | ⌘⇧R |
| Open URL | ⌘⇧O |
| Favorite | ⌘D |
| Delete item | ⌘⌫ |
| Generator | ⌘G |
| Lock | ⌘L |
| Settings | ⌘, |
| Toggle sidebar | ⌃⌘S |
| Sidebar row | ⌘1 … ⌘9 |
| Close window | ⌘W |

## If something goes wrong

Settings ▸ Security ▸ "Copy diagnostics" puts a short technical summary on the clipboard with no secrets in it. Backups can be opened and restored from Settings ▸ Sync & Backup.
