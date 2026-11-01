# Scenario functions. Each runs after lab_begin and records problems with `fail`.
# Devices edit with `vault edit`, the fake cloud delivers (plain overwrite or conflict copy) and the
# receiver runs `vault sync`; both sides are then compared through the CLI.

SCENARIOS="different_fields same_field_later_wins delete_vs_edit rename_vs_favorite tag_vs_icon
field_removal_cycle three_devices_removal_offline attachment_blob_order conflict_copy_sibling
conflict_copy_inpackage conflict_copy_numbered_sibling conflict_copy_numbered_inpackage stale_sender_three_devices v1_upgrade_propagates concurrent_add_same_second concurrent_same_field_same_time
concurrent_add_shared_package divergent_concurrent_adds"

pair_with_item() { # new vault on A holding "Item", delivered to B
  new_vault A
  mk_item A Item
  deliver A B
  same_view A B "setup"
}

converged() { # converged X Y what: same view and same bytes after two rounds
  exchange "$1" "$2"
  same_view "$1" "$2" "$3"
  same_bytes "$1" "$2" "$3"
}

different_fields() {
  pair_with_item
  ed A Item --set username=ua
  ed B Item --set password=pb
  converged A B "different fields"
  expect_eq "$(fval A Item username)/$(fval A Item password)" "ua/pb" "A field values"
  expect_eq "$(fval B Item username)/$(fval B Item password)" "ua/pb" "B field values"
}

same_field_later_wins() {
  new_vault A
  mk_item A I1
  mk_item A I2
  deliver A B
  ed A I1 --set notes=a1
  ed B I1 --set notes=b1 # later
  ed B I2 --set notes=b2
  ed A I2 --set notes=a2 # later
  converged A B "same field"
  expect_eq "$(fval A I1 notes)/$(fval A I2 notes)" "b1/a2" "A notes"
  expect_eq "$(fval B I1 notes)/$(fval B I2 notes)" "b1/a2" "B notes"
}

delete_vs_edit() {
  new_vault A
  mk_item A D1
  mk_item A D2
  deliver A B
  vx A rm D1 >/dev/null || fail "A rm D1"
  sleep 0.06
  ed B D1 --set notes=resurrect # edit after the delete: the item comes back
  ed B D2 --set notes=early
  vx A rm D2 >/dev/null || fail "A rm D2" # delete after the edit: the delete sticks
  converged A B "delete vs edit"
  expect_eq "$(titles A)" "D1 " "A titles"
  expect_eq "$(titles B)" "D1 " "B titles"
  expect_eq "$(fval A D1 notes)" resurrect "A D1 notes"
}

rename_vs_favorite() {
  pair_with_item
  ed A Item --title Renamed
  ed B Item --favorite
  converged A B "rename vs favorite"
  expect_eq "$(titles A)" "Renamed " "A title"
  expect_eq "$(vx A list --favorites | awk '{print $2}' | tr '\n' ' ')" "Renamed " "A favorites"
  expect_eq "$(vx B list --favorites | awk '{print $2}' | tr '\n' ' ')" "Renamed " "B favorites"
}

tag_vs_icon() {
  pair_with_item
  ed A Item --tag extra
  ed B Item --icon letter:#abcdef
  converged A B "tag vs icon"
  vx A get Item 2>&1 | grep "^tags:.*extra" >/dev/null || fail "A lost the tag"
  vx B get Item 2>&1 | grep "^tags:.*extra" >/dev/null || fail "B lost the tag"
  vx A get Item 2>&1 | grep "^Icon: letter #abcdef" >/dev/null || fail "A lost the icon"
  vx B get Item 2>&1 | grep "^Icon: letter #abcdef" >/dev/null || fail "B lost the icon"
}

field_removal_cycle() {
  local f
  pair_with_item
  ed A Item --add text:Extra=e0
  exchange A B
  f="$(fid A Item Extra)"
  [ -n "$f" ] || { fail "no Extra field id"; return 0; }
  ed A Item --rm-field "$f"
  ed B Item --set "$f=edited" # later than the removal: the field survives
  converged A B "removed then edited"
  expect_eq "$(fval A Item Extra)" edited "A Extra after edit"
  expect_eq "$(fval B Item Extra)" edited "B Extra after edit"
  ed A Item --rm-field "$f" # removed again, later than the edit
  converged A B "removed again"
  expect_eq "$(fid A Item Extra)" "" "A Extra after second removal"
  expect_eq "$(fid B Item Extra)" "" "B Extra after second removal"
}

three_devices_removal_offline() {
  local f
  pair_with_item
  ed A Item --add text:Extra=e0
  exchange A B
  deliver B C
  f="$(fid A Item Extra)"
  [ -n "$f" ] || { fail "no Extra field id"; return 0; }
  ed A Item --rm-field "$f"
  deliver A B
  ed C Item --set username=uc # C is offline and edits meanwhile
  deliver B C --delay 100     # C comes back online; it has unsynced edits, so a conflict copy
  expect_eq "$(fid C Item Extra)" "" "C Extra after returning"
  expect_eq "$(fval C Item username)" uc "C keeps its own edit"
  exchange C A
  exchange A B
  exchange B C
  same_view A B "A vs B"
  same_view B C "B vs C"
  expect_eq "$(fid B Item Extra)" "" "B Extra"
  expect_eq "$(fval A Item username)" uc "A got C's edit"
}

attachment_blob_order() {
  local id st
  new_vault A
  mk_item A WithFile
  deliver A B
  head -c 5000 /dev/urandom >"$LAB/blob.bin"
  vx A attach add WithFile "$LAB/blob.bin" >/dev/null || fail "attach add"
  deliver A B --only vault
  st="$(vx B attach list WithFile 2>&1 | awk '{print $NF}')"
  case "$st" in missing | not-downloaded) ;; *) fail "before blob copy B shows state '$st', want missing or not-downloaded" ;; esac
  id="$(vx B attach list WithFile 2>&1 | awk '{print $1}' | head -1)"
  vx B attach get WithFile "$id" "$LAB/early.bin" >/dev/null 2>&1 && fail "B read an attachment whose blob has not arrived"
  [ -e "$LAB/early.bin" ] && fail "failed attach get left an output file"
  deliver A B --only blobs --delay 100
  expect_eq "$(vx B attach list WithFile 2>&1 | awk '{print $NF}')" present "state after blob copy"
  vx B attach get WithFile "$id" "$LAB/late.bin" >/dev/null 2>&1 || fail "B attach get after blob copy"
  cmp -s "$LAB/blob.bin" "$LAB/late.bin" || fail "attachment bytes differ on B"
  same_view A B "after blob copy"
}

conflict_shape() { # conflict_shape sibling|inpackage|sibling-n|inpackage-n
  local shape="$1" n
  pair_with_item
  mk_item A OnlyA
  ed A Item --set notes=fromA
  mk_item B OnlyB
  deliver A B --conflict "$shape"
  case "$LAST_SYNC" in *"synced: 1 conflict cop"*) ;; *) fail "expected one absorbed copy, sync said: $LAST_SYNC" ;; esac
  case "$shape" in
    sibling | sibling-n) [ "$(ls "$LAB/B")" = main.vault ] || fail "sibling copy still in place after sync: $(ls "$LAB/B" | tr '\n' '|')" ;;
    *) ls "$LAB/B/main.vault" | grep -E '^vault .*\.bin$' >/dev/null && fail "in-package copy still in place after sync" ;;
  esac
  n="$(ls "$LAB/B/main.vault/backups" 2>/dev/null | grep -c '^conflict-')"
  [ "$n" -ge 1 ] || fail "conflict copy was not moved to backups/"
  expect_eq "$(titles B)" "Item OnlyA OnlyB " "B items after absorbing"
  expect_eq "$(fval B Item notes)" fromA "B notes"
  converged A B "after $shape conflict"
  expect_eq "$(titles A)" "Item OnlyA OnlyB " "A items"
}
conflict_copy_sibling() { conflict_shape sibling; }
conflict_copy_inpackage() { conflict_shape inpackage; }
conflict_copy_numbered_sibling() { conflict_shape sibling-n; }
conflict_copy_numbered_inpackage() { conflict_shape inpackage-n; }

# A stale sender must never plain-overwrite a receiver whose newer edit only reached a third device.
# Under a per-device "unsynced edits" rule B counted as clean after uploading, A's old file replaced
# it, and the title edit survived only on C. Driven through the model, which expects all three devices
# to end with both edits.
stale_sender_three_devices() {
  m_init
  new_vault A
  mop add A Item
  mdeliver A B
  mdeliver A C
  mop edit B Item --title Edited
  mdeliver B C
  mop edit A Item --favorite # A never saw B's edit
  mdeliver A B               # must be a conflict copy, not an overwrite
  expect_eq "$LAST_MODE" conflict "stale sender's delivery mode"
  expect_eq "$(titles B)" "Edited " "B keeps its title edit"
  mexchange B C
  mexchange A B
  mexchange B C
  mexchange A C
  mcheck --bytes A B C
  expect_eq "$(titles C)" "Edited " "C title"
  expect_eq "$(vx A list --favorites | awk '{print $2}' | tr '\n' ' ')" "Edited " "A favorite on the renamed item"
}

v1_upgrade_propagates() {
  local fix="$ROOT/crates/vault-core/tests/fixtures/v1-basic.vault" n first
  LAB_PW="correct horse battery staple"
  mkdir -p "$LAB/A/main.vault" && cp "$fix" "$LAB/A/main.vault/vault.bin" || { fail "fixture copy"; return 0; }
  deliver A B
  deliver A C
  expect_eq "$(fmt_version "$(dpath B)")" 0001 "B starts at version 1"
  n="$(titles A)"
  first="$(echo "$n" | awk '{print $1}')"
  ed C "$first" --favorite # C edits on version 1 while A upgrades
  vx A upgrade --allow-weak >/dev/null 2>&1 || fail "A upgrade"
  expect_eq "$(fmt_version "$(dpath A)")" 0002 "A version after upgrade"
  expect_eq "$(titles B)" "$n" "B opens v1 before sync"
  deliver A B --delay 100 # B has no edits: plain overwrite
  expect_eq "$(fmt_version "$(dpath B)")" 0002 "B version after sync"
  expect_eq "$(titles B)" "$n" "B opens with the old password after sync"
  deliver A C # C has an edit: the upgraded file arrives as a conflict copy
  expect_eq "$(fmt_version "$(dpath C)")" 0002 "C version after absorbing"
  expect_eq "$(titles C)" "$n" "C opens with the old password"
  expect_eq "$(vx C list --favorites | awk '{print $2}' | tr '\n' ' ')" "$first " "C keeps its edit"
  ed B "$first" --set notes=afterUpgrade
  expect_eq "$(fmt_version "$(dpath B)")" 0002 "B save keeps version 2"
  exchange B A
  exchange A C
  exchange A B
  same_view A B "A vs B"
  same_view A C "A vs C"
  expect_eq "$(fval C "$first" notes)" afterUpgrade "C got B's edit"
}

concurrent_add_same_second() {
  local i pids="" p
  new_vault A
  deliver A B
  for i in 1 2 3; do
    (vx A add --title "a$i" --username "ua$i" >"$LAB/o-a$i" 2>&1) &
    pids="$pids $!"
    (vx B add --title "b$i" --username "ub$i" >"$LAB/o-b$i" 2>&1) &
    pids="$pids $!"
  done
  for p in $pids; do wait "$p" || fail "a concurrent add failed: $(cat "$LAB"/o-* | head -2)"; done
  converged A B "concurrent adds"
  expect_eq "$(titles A)" "a1 a2 a3 b1 b2 b3 " "A titles"
}

concurrent_same_field_same_time() {
  pair_with_item
  (vx A edit Item --set notes=fromA >"$LAB/o-a" 2>&1) &
  local pa=$!
  (vx B edit Item --set notes=fromB >"$LAB/o-b" 2>&1) &
  local pb=$!
  wait "$pa" || fail "A edit failed"
  wait "$pb" || fail "B edit failed"
  converged A B "same field at the same time"
  expect_eq "$(fval A Item notes)" "$(fval B Item notes)" "both sides pick the same value"
}

# Two devices working on one package at the same moment (the cloud already delivered
# everything instantly): the advisory lock and pre-write merge must keep every item.
concurrent_add_shared_package() {
  local i pids="" p fails=0 n
  new_vault A
  mkdir -p "$LAB/shared"
  cp -R "$(dpath A)" "$LAB/shared/main.vault"
  for i in 1 2 3 4 5 6; do
    (VX_FILE="$LAB/shared/main.vault" vx A add --title "a$i" >"$LAB/o-a$i" 2>&1) &
    pids="$pids $!"
    (VX_FILE="$LAB/shared/main.vault" vx B add --title "b$i" >"$LAB/o-b$i" 2>&1) &
    pids="$pids $!"
  done
  for p in $pids; do wait "$p" || fails=$((fails + 1)); done
  [ "$fails" = 0 ] || fail "$fails of 12 concurrent adds failed: $(cat "$LAB"/o-* | sort | uniq -c | head -3)"
  n="$(VX_FILE="$LAB/shared/main.vault" vx A list 2>/dev/null | wc -l | tr -d ' ')"
  expect_eq "$n" 12 "items after 12 concurrent adds"
  ls -a "$LAB/shared/main.vault" | grep -q "tmp" && fail "tmp file left behind"
  return 0
}

divergent_concurrent_adds() {
  pair_with_item
  mk_item A a1; mk_item A a2
  mk_item B b1; mk_item B b2
  deliver A B # B has unsynced adds: arrives as a conflict copy
  case "$LAST_SYNC" in *"synced: 1 conflict cop"*) ;; *) fail "expected one absorbed copy, sync said: $LAST_SYNC" ;; esac
  expect_eq "$(titles B)" "Item a1 a2 b1 b2 " "B after absorbing"
  converged A B "divergent adds"
  expect_eq "$(titles A)" "Item a1 a2 b1 b2 " "A titles"
}
