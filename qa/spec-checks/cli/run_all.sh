#!/usr/bin/env bash
# Black-box CLI checks against target/debug/vault (README "CLI quick example", 02/03 specs).
# Usage: qa/spec-checks/cli/run_all.sh   (after `cargo build -p vault-cli`)
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
V="$ROOT/target/debug/vault"
TMPROOT="$ROOT/qa/spec-checks/tmp"
mkdir -p "$TMPROOT"
T="$(mktemp -d "$TMPROOT/cli-XXXXXX")"
trap 'rm -rf "$T"' EXIT
export MPW="tidy-Walrus-orbit-Velvet-42"
export VAULT_FILE="$T/main.vault"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL $1"; shift; for l in "$@"; do echo "     $l"; done; }
v()    { "$V" --password-env MPW "$@"; }
mode() { stat -f %Lp "$1"; }

# ---- init -------------------------------------------------------------------------------
# README: "`init` refuses a master password under 50 bits unless `--allow-weak` is given."
WEAK=password1 "$V" --vault "$T/weak.vault" --password-env WEAK init --kdf-test-params >"$T/o" 2>&1
rc=$?
if [ $rc -ne 0 ] && [ ! -e "$T/weak.vault/vault.bin" ]; then ok "init refuses weak master password"; else bad "init refuses weak master password" "rc=$rc $(cat "$T/o")"; fi
WEAK=password1 "$V" --vault "$T/weak.vault" --password-env WEAK init --kdf-test-params --allow-weak >"$T/o" 2>&1 \
  && ok "init --allow-weak accepts weak password" || bad "init --allow-weak" "$(cat "$T/o")"

v init --kdf-test-params >"$T/o" 2>&1 && ok "init strong password" || bad "init strong password" "$(cat "$T/o")"
# 03 §1: <name>.vault is a package directory containing vault.bin; §2 mode 0600
if [ -d "$VAULT_FILE" ] && [ -f "$VAULT_FILE/vault.bin" ]; then ok "init creates package dir with vault.bin"; else bad "init package layout" "$(ls -la "$T")"; fi
[ "$(mode "$VAULT_FILE/vault.bin")" = "600" ] && ok "vault.bin mode 0600" || bad "vault.bin mode 0600" "mode=$(mode "$VAULT_FILE/vault.bin")"
# init must not clobber an existing vault
before=$(shasum "$VAULT_FILE/vault.bin")
OTHER="another-Strong-passphrase-77" "$V" --password-env OTHER init --kdf-test-params >"$T/o" 2>&1
rc=$?
after=$(shasum "$VAULT_FILE/vault.bin")
if [ $rc -ne 0 ] && [ "$before" = "$after" ]; then ok "init refuses to overwrite an existing vault"; else bad "init refuses to overwrite an existing vault" "rc=$rc $(cat "$T/o")"; fi

# ---- add / get / list -------------------------------------------------------------------
export VAULT_ITEM_PASSWORD="item-Pa55-secret"
export VAULT_ITEM_TOTP="otpauth://totp/GitHub:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub"
v add --template login --title GitHub --username me --password-field --totp-field --url https://github.com --tag work >"$T/o" 2>&1 \
  && ok "add login with --password-field --totp-field" || bad "add login" "$(cat "$T/o")"
v add --template note --title "Secret note" --notes "line1" >"$T/o" 2>&1 && ok "add note" || bad "add note" "$(cat "$T/o")"
v get GitHub >"$T/o" 2>&1
if grep -q "me" "$T/o" && ! grep -q "$VAULT_ITEM_PASSWORD" "$T/o"; then ok "get without --reveal hides password"; else bad "get hides password" "$(cat "$T/o")"; fi
v get GitHub --reveal >"$T/o" 2>&1
grep -q "$VAULT_ITEM_PASSWORD" "$T/o" && ok "get --reveal shows password" || bad "get --reveal" "$(cat "$T/o")"
grep -q "GEZDGNBV" "$T/o" && echo "INFO get --reveal prints the TOTP secret URI" || true
v list >"$T/o" 2>&1
grep -q GitHub "$T/o" && grep -q "Secret note" "$T/o" && ok "list shows both items" || bad "list" "$(cat "$T/o")"
# 05 §2.3 templates add one tag (#login, #note)
v list --tag login >"$T/o" 2>&1
if grep -q GitHub "$T/o" && ! grep -q "Secret note" "$T/o"; then ok "template login adds tag login"; else bad "template tag login" "$(cat "$T/o")"; fi
v list --tag note >"$T/o" 2>&1
grep -q "Secret note" "$T/o" && ok "template note adds tag note" || bad "template tag note" "$(cat "$T/o")"
v list --tag work >"$T/o" 2>&1
grep -q GitHub "$T/o" && ok "--tag on add" || bad "--tag on add" "$(cat "$T/o")"

# ---- totp vs independent computation ------------------------------------------------------
code=$(v totp GitHub 2>/dev/null | tr -dc '0-9' | head -c 6)
exp=$(python3 -I -c '
import hmac,hashlib,struct,time,base64
k=base64.b32decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
c=int(time.time())//30
h=hmac.new(k,struct.pack(">Q",c),hashlib.sha1).digest()
o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))')
exp2=$(python3 -I -c '
import hmac,hashlib,struct,time,base64
k=base64.b32decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
c=int(time.time())//30-1
h=hmac.new(k,struct.pack(">Q",c),hashlib.sha1).digest()
o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))')
if [ "$code" = "$exp" ] || [ "$code" = "$exp2" ]; then ok "totp matches independent HMAC-SHA1"; else bad "totp" "cli=$code expected=$exp"; fi

# ---- wrong password / missing env ---------------------------------------------------------
WRONGPW="not-the-Right-one-99" "$V" --password-env WRONGPW list >"$T/o" 2>&1
rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 101 ] && ! grep -q "not-the-Right-one-99" "$T/o"; then ok "wrong password: clean error, no echo"; else bad "wrong password" "rc=$rc $(cat "$T/o")"; fi
"$V" --password-env NO_SUCH_VAR_XYZ list >"$T/o" 2>&1
rc=$?
[ $rc -ne 0 ] && [ $rc -ne 101 ] && ok "missing password env var: clean error" || bad "missing env var" "rc=$rc $(cat "$T/o")"
"$V" --password-env MPW --vault "$T/nope.vault" list >"$T/o" 2>&1
rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 101 ] && [ ! -e "$T/nope.vault" ]; then ok "nonexistent vault: clean error, nothing created"; else bad "nonexistent vault" "rc=$rc $(cat "$T/o")"; fi
echo "plain file" >"$T/plain.vault"
"$V" --password-env MPW --vault "$T/plain.vault" list >"$T/o" 2>&1
rc=$?
[ $rc -ne 0 ] && [ $rc -ne 101 ] && ok "plain file instead of package: clean error" || bad "plain file path" "rc=$rc $(cat "$T/o")"

# ---- gen ----------------------------------------------------------------------------------
p=$("$V" gen 2>/dev/null | tail -1)
[ ${#p} -eq 20 ] && ok "gen default length 20" || bad "gen default length" "got '${#p}'"
p=$("$V" gen --length 4 2>/dev/null | tail -1)
if [[ "$p" =~ [a-z] && "$p" =~ [A-Z] && "$p" =~ [0-9] && "$p" =~ [^a-zA-Z0-9] ]]; then ok "gen --length 4 has every class (02 guarantee 10)"; else bad "gen length 4 classes" "$p"; fi
p=$("$V" gen --no-symbols --no-digits --no-upper --length 30 2>/dev/null | tail -1)
[[ "$p" =~ ^[a-z]{30}$ ]] && ok "gen class switches" || bad "gen class switches" "$p"
p=$("$V" gen --passphrase --words 5 2>/dev/null | tail -1)
n=$(echo "$p" | awk -F- '{print NF}')
[ "$n" -ge 5 ] && ok "gen --passphrase --words 5" || bad "gen passphrase" "$p"
"$V" gen --length 0 >"$T/o" 2>&1; rc=$?
[ $rc -ne 101 ] && ok "gen --length 0 no panic" || bad "gen --length 0 panics" "$(cat "$T/o")"

# ---- rm -----------------------------------------------------------------------------------
v add --title Temp --username t >/dev/null 2>&1
v rm Temp >"$T/o" 2>&1 && ok "rm" || bad "rm" "$(cat "$T/o")"
v list >"$T/o" 2>&1
! grep -q "^.*Temp" "$T/o" && ok "rm hides item from list" || bad "rm list" "$(cat "$T/o")"
v get Temp >"$T/o" 2>&1; rc=$?
[ $rc -ne 0 ] && [ $rc -ne 101 ] && ok "get removed item fails cleanly" || bad "get removed item" "rc=$rc $(cat "$T/o")"

# ---- duplicate titles ---------------------------------------------------------------------
v add --title Dup --username one >/dev/null 2>&1
v add --title Dup --username two >/dev/null 2>&1
v rm Dup >"$T/o" 2>&1; rc=$?
v list >"$T/o2" 2>&1
cnt=$(grep -c "Dup" "$T/o2")
if [ $rc -ne 0 ] && [ "$cnt" = "2" ]; then ok "rm with ambiguous title refuses"; else echo "INFO rm ambiguous title: rc=$rc remaining=$cnt $(head -2 "$T/o")"; fi

# ---- export -------------------------------------------------------------------------------
v export --out "$T/e.csv" >"$T/o" 2>&1 </dev/null; rc=$?
if [ $rc -ne 0 ] && [ ! -e "$T/e.csv" ]; then ok "export without --yes refuses (non-interactive)"; else echo "INFO export without --yes: rc=$rc"; rm -f "$T/e.csv"; fi
v export --out "$T/e.csv" --yes >"$T/o" 2>&1 && ok "export --yes" || bad "export --yes" "$(cat "$T/o")"
[ -f "$T/e.csv" ] && [ "$(mode "$T/e.csv")" = "600" ] && ok "export file mode 0600" || bad "export mode" "mode=$(mode "$T/e.csv" 2>/dev/null)"
grep -q "$VAULT_ITEM_PASSWORD" "$T/e.csv" && ok "export contains passwords" || bad "export content" "$(head -3 "$T/e.csv")"
echo keep >"$T/exists.csv"
v export --out "$T/exists.csv" --yes >"$T/o" 2>&1; rc=$?
[ $rc -ne 0 ] && [ "$(cat "$T/exists.csv")" = "keep" ] && ok "export refuses to overwrite without --force" || bad "export overwrite" "rc=$rc"
ln -s "$T/target-of-link" "$T/link.csv"
v export --out "$T/link.csv" --yes --force >"$T/o" 2>&1; rc=$?
# Not counted as a failure: --force is an explicit overwrite of a user-chosen path; the result is 0600.
if [ -e "$T/target-of-link" ]; then echo "INFO export --force writes through a symlink at --out (target mode $(mode "$T/target-of-link"))"; else ok "export --force does not follow symlink"; fi

# ---- import csv ---------------------------------------------------------------------------
export VAULT_FILE="$T/imp.vault"
v init --kdf-test-params >/dev/null 2>&1
v import --format csv --in "$T/e.csv" >"$T/o" 2>&1 && ok "import --format csv of own export" || bad "import csv" "$(cat "$T/o")"
v get GitHub --reveal >"$T/o" 2>&1
grep -q "$VAULT_ITEM_PASSWORD" "$T/o" && ok "imported password intact" || bad "import content" "$(cat "$T/o")"
v import --format nope --in "$T/e.csv" >"$T/o" 2>&1; rc=$?
[ $rc -ne 0 ] && [ $rc -ne 101 ] && ok "import unknown format: clean error" || bad "import unknown format" "rc=$rc"

# ---- attachments --------------------------------------------------------------------------
export VAULT_FILE="$T/main.vault"
head -c 2500000 /dev/urandom >"$T/blob.bin"
v attach add GitHub "$T/blob.bin" >"$T/o" 2>&1 && ok "attach add" || bad "attach add" "$(cat "$T/o")"
v attach list GitHub >"$T/o" 2>&1
grep -q "blob.bin" "$T/o" && ok "attach list" || bad "attach list" "$(cat "$T/o")"
f=$(ls "$VAULT_FILE/attachments/" | head -1)
[[ "$f" =~ ^[0-9a-f]{32}\.bin$ ]] && ok "blob named <32 hex>.bin" || bad "blob name" "$f"
[ "$(mode "$VAULT_FILE/attachments/$f")" = "600" ] && ok "blob mode 0600" || bad "blob mode" "$(mode "$VAULT_FILE/attachments/$f")"
aid=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$T/o" | head -1)
v attach get GitHub "${aid:-blob.bin}" "$T/out.bin" >"$T/o" 2>&1 || v attach get GitHub "${aid:-blob.bin}" --out "$T/out.bin" >"$T/o" 2>&1
if cmp -s "$T/blob.bin" "$T/out.bin"; then ok "attach get round trip"; else bad "attach get" "$(cat "$T/o")" "$("$V" attach get --help | head -5)"; fi
[ -f "$T/out.bin" ] && [ "$(mode "$T/out.bin")" = "600" ] && ok "attach get mode 0600" || bad "attach get mode" "$(mode "$T/out.bin" 2>/dev/null)"
echo keep >"$T/keep.bin"
v attach get GitHub "${aid:-blob.bin}" "$T/keep.bin" >"$T/o" 2>&1 || v attach get GitHub "${aid:-blob.bin}" --out "$T/keep.bin" >>"$T/o" 2>&1
[ "$(cat "$T/keep.bin")" = "keep" ] && ok "attach get refuses to overwrite" || bad "attach get overwrote an existing file"
head -c 100000001 /dev/zero >"$T/huge.bin" 2>/dev/null
v attach add GitHub "$T/huge.bin" >"$T/o" 2>&1; rc=$?
[ $rc -ne 0 ] && [ $rc -ne 101 ] && ok "attach add >100 MB refused" || bad "attach >100MB" "rc=$rc"
rm -f "$T/huge.bin"
v attach rm GitHub "${aid:-blob.bin}" >"$T/o" 2>&1 && ok "attach rm" || bad "attach rm" "$(cat "$T/o")"
v attach list GitHub >"$T/o" 2>&1
! grep -q "blob.bin" "$T/o" && ok "attach list after rm" || bad "attach list after rm" "$(cat "$T/o")"

# ---- concurrent writers (03 §2 V-02) -------------------------------------------------------
export VAULT_FILE="$T/cc.vault"
v init --kdf-test-params >/dev/null 2>&1
pids=()
for i in $(seq 1 12); do v add --title "cc$i" --username "u$i" >"$T/cc$i.log" 2>&1 & pids+=($!); done
fails=0; for p in "${pids[@]}"; do wait "$p" || fails=$((fails+1)); done
n=$(v list 2>/dev/null | grep -c "cc[0-9]")
if [ "$n" = "12" ] && [ "$fails" = "0" ]; then ok "12 concurrent adds: no lost items"; else bad "concurrent adds" "items=$n failed_procs=$fails" "$(cat "$T"/cc*.log | sort | uniq -c | head -5)"; fi
ls -a "$VAULT_FILE" | grep -q "tmp" && bad "tmp files left after concurrent writers" "$(ls -a "$VAULT_FILE")" || ok "no tmp left after concurrent writers"

# ---- corrupted vault ----------------------------------------------------------------------
cp "$VAULT_FILE/vault.bin" "$T/good.bin"
sz=$(stat -f %z "$T/good.bin")
for cut in 3 9 20 $((sz/2)) $((sz-1)); do
  head -c $cut "$T/good.bin" >"$VAULT_FILE/vault.bin"
  v list >"$T/o" 2>&1; rc=$?
  if [ $rc -eq 0 ] || [ $rc -eq 101 ]; then bad "truncated vault at $cut" "rc=$rc $(head -2 "$T/o")"; fi
  v add --title X >"$T/o" 2>&1; rc=$?
  cur=$(stat -f %z "$VAULT_FILE/vault.bin")
  if [ $rc -eq 0 ] || [ "$cur" != "$cut" ]; then bad "add on truncated vault at $cut wrote/overwrote" "rc=$rc size=$cur"; fi
done
ok "truncated vault: list/add fail cleanly, file untouched (unless reported above)"
cp "$T/good.bin" "$VAULT_FILE/vault.bin"

# ---- upgrade (01 §9 "the CLI exposes it as an explicit command"; README `vault upgrade`) ----------
FIX="$ROOT/crates/vault-core/tests/fixtures"
export FPW="correct horse battery staple"
fv() { xxd -s 4 -l 2 -p "$1"; }
mkdir -p "$T/up.vault"; cp "$FIX/v1-basic.vault" "$T/up.vault/vault.bin"
[ "$(fv "$T/up.vault/vault.bin")" = "0001" ] && ok "fixture v1-basic is version 1" || bad "fixture version" "$(fv "$T/up.vault/vault.bin")"
"$V" --vault "$T/up.vault" --password-env FPW list >"$T/o" 2>&1 && ok "v1 vault opens before upgrade" || bad "v1 list" "$(cat "$T/o")"
"$V" --vault "$T/up.vault" --password-env FPW add --title AfterV1 --username z >"$T/o" 2>&1
[ "$(fv "$T/up.vault/vault.bin")" = "0001" ] && ok "a save never changes a v1 file's version" || bad "add changed version" "$(fv "$T/up.vault/vault.bin")"
cp "$T/up.vault/vault.bin" "$T/up-before.bin"
BADPW="wrong horse battery staple" "$V" --vault "$T/up.vault" --password-env BADPW upgrade --allow-weak >"$T/o" 2>&1; rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 101 ] && cmp -s "$T/up-before.bin" "$T/up.vault/vault.bin" && ! grep -q "wrong horse" "$T/o"; then ok "upgrade with wrong password: clean error, file untouched"; else bad "upgrade wrong password" "rc=$rc $(cat "$T/o")"; fi
"$V" --vault "$T/up.vault" --password-env FPW upgrade --allow-weak >"$T/o" 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(fv "$T/up.vault/vault.bin")" = "0002" ] && ok "upgrade writes version 2" || bad "upgrade" "rc=$rc $(cat "$T/o")"
"$V" --vault "$T/up.vault" --password-env FPW get AfterV1 >"$T/o" 2>&1 && ok "upgraded vault opens, items kept" || bad "after upgrade" "$(cat "$T/o")"
cp "$T/up.vault/vault.bin" "$T/up-v2.bin"
"$V" --vault "$T/up.vault" --password-env FPW upgrade --allow-weak >"$T/o" 2>&1; rc=$?
[ $rc -eq 0 ] && cmp -s "$T/up-v2.bin" "$T/up.vault/vault.bin" && ok "second upgrade is a no-op (file bytes unchanged)" || { [ $rc -eq 0 ] && echo "INFO second upgrade rewrote the file: $(cat "$T/o")" || bad "second upgrade" "rc=$rc $(cat "$T/o")"; }
"$V" --vault "$T/up.vault" --password-env FPW add --title AfterV2 >"$T/o" 2>&1
"$V" --vault "$T/up.vault" --password-env FPW get AfterV2 --ids >"$T/o" 2>&1
grep -qE '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-' "$T/o" && ok "get --ids prints v4 field ids" || bad "get --ids" "$(cat "$T/o")"
"$V" --vault "$T/up.vault" --password-env FPW get AfterV1 --ids >"$T/o" 2>&1
grep -qE '[0-9a-f]{8}-[0-9a-f]{4}-[45][0-9a-f]{3}-' "$T/o" && ok "get --ids on a migrated item" || bad "get --ids migrated" "$(cat "$T/o")"

# ---- secrets in error output / leaking ----------------------------------------------------
v get NoSuchItem >"$T/o" 2>&1
grep -q "$MPW" "$T/o" && bad "error output contains the master password" || ok "no master password in error output"

# =====================================================================================
# 2026-11-01 additions: `edit`, `sync`, VAULT_DEVICE_ID (00 phase 1 "later dev-tool additions"),
# conflict copies of both shapes via `sync` (03 §6), NFD names (03 §3/§6), concurrent editors.
# =====================================================================================
export VAULT_FILE="$T/ed.vault"
v init --kdf-test-params >/dev/null 2>&1
v add --title Site --username alice >/dev/null 2>&1
v edit Site --title "Site 2" --favorite --tag red --tag blue >"$T/o" 2>&1 && ok "edit title/favorite/tags" || bad "edit title/favorite/tags" "$(cat "$T/o")"
v list --tag red >"$T/o" 2>&1
grep -q "Site 2" "$T/o" && ok "edit --tag visible in list --tag" || bad "edit --tag" "$(cat "$T/o")"
v edit "Site 2" --untag red >/dev/null 2>&1
v list --tag red >"$T/o" 2>&1
! grep -q "Site 2" "$T/o" && ok "edit --untag" || bad "edit --untag" "$(cat "$T/o")"
export EDSECRET="edit-Secret-Value-913"
v edit "Site 2" --set-env "password=EDSECRET" >"$T/o" 2>&1; rc=$?
if [ $rc -eq 0 ] && ! grep -q "$EDSECRET" "$T/o"; then ok "edit --set-env (value not echoed)"; else bad "edit --set-env" "rc=$rc $(cat "$T/o")"; fi
v get "Site 2" --reveal >"$T/o" 2>&1
grep -q "$EDSECRET" "$T/o" && ok "edit --set-env value stored" || bad "edit --set-env stored" "$(cat "$T/o")"
v edit "Site 2" --set-env "password=NO_SUCH_ENV_VAR_QA" >"$T/o" 2>&1; rc=$?
[ $rc -ne 0 ] && [ $rc -ne 101 ] && ok "edit --set-env missing var: clean error" || bad "edit --set-env missing var" "rc=$rc $(cat "$T/o")"
v edit "Site 2" --add "text:dup=one" --add "text:dup=two" >"$T/o" 2>&1 && ok "edit --add two same-named fields" || bad "edit --add dup" "$(cat "$T/o")"
cp "$VAULT_FILE/vault.bin" "$T/ed-before.bin"
v edit "Site 2" --set "dup=three" >"$T/o" 2>&1; rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 101 ] && cmp -s "$T/ed-before.bin" "$VAULT_FILE/vault.bin"; then ok "edit --set on a shared name is refused, file untouched"; else bad "edit --set ambiguous name" "rc=$rc $(cat "$T/o")"; fi
fid=$(v get "Site 2" --ids 2>/dev/null | grep -i "dup" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
v edit "Site 2" --rm-field "$fid" >"$T/o" 2>&1; rc=$?
n=$(v get "Site 2" --reveal 2>/dev/null | grep -ci "dup")
[ $rc -eq 0 ] && [ "$n" = "1" ] && ok "edit --rm-field by id removes exactly one field" || bad "edit --rm-field" "rc=$rc dup-count=$n $(cat "$T/o")"
v edit "Site 2" --add "section:Login details" >"$T/o" 2>&1 && ok "edit --add section" || bad "edit --add section" "$(cat "$T/o")"
v edit "Site 2" --add "bogus:x=y" >"$T/o" 2>&1; rc=$?
[ $rc -ne 0 ] && [ $rc -ne 101 ] && ok "edit --add unknown kind: clean error" || bad "edit --add unknown kind" "rc=$rc $(cat "$T/o")"
v edit "Site 2" --icon "symbol:NoSuchIcon:#zzzzzz" >"$T/o" 2>&1; rc=$?
[ $rc -ne 101 ] && ok "edit --icon malformed: no panic (rc=$rc)" || bad "edit --icon panics" "$(cat "$T/o")"
v edit "Site 2" --rm-field "00000000-0000-0000-0000-000000000000" >"$T/o" 2>&1; rc=$?
[ $rc -ne 0 ] && [ $rc -ne 101 ] && ok "edit --rm-field unknown id: clean error" || bad "edit --rm-field unknown id" "rc=$rc $(cat "$T/o")"

# VAULT_DEVICE_ID: a malformed value must not be silently replaced by a random id or panic
cp "$VAULT_FILE/vault.bin" "$T/ed-before.bin"
VAULT_DEVICE_ID="not-a-uuid" "$V" --password-env MPW add --title DevBad >"$T/o" 2>&1; rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 101 ] && cmp -s "$T/ed-before.bin" "$VAULT_FILE/vault.bin"; then ok "VAULT_DEVICE_ID malformed: clean error, nothing written"; else bad "VAULT_DEVICE_ID malformed" "rc=$rc $(cat "$T/o")"; fi

# concurrent editors of one item (03 §2 lock): every --set lands
pids=()
for i in $(seq 1 10); do v edit "Site 2" --add "text:c$i=v$i" >"$T/ce$i.log" 2>&1 & pids+=($!); done
fails=0; for p in "${pids[@]}"; do wait "$p" || fails=$((fails+1)); done
n=$(v get "Site 2" --reveal 2>/dev/null | grep -cE "c([0-9]|10)\b")
[ "$n" = "10" ] && [ "$fails" = "0" ] && ok "10 concurrent edit --add on one item: none lost" || bad "concurrent edits" "fields=$n failed=$fails $(cat "$T"/ce*.log | sort | uniq -c | head -3)"

# mixed concurrent writers: add + edit + sync
pids=()
for i in $(seq 1 5); do v add --title "mx$i" >"$T/mx$i.log" 2>&1 & pids+=($!); v edit "Site 2" --set "c$i=w$i" >"$T/me$i.log" 2>&1 & pids+=($!); v sync >"$T/ms$i.log" 2>&1 & pids+=($!); done
fails=0; for p in "${pids[@]}"; do wait "$p" || fails=$((fails+1)); done
n=$(v list 2>/dev/null | grep -c "mx[0-9]")
w=$(v get "Site 2" --reveal 2>/dev/null | grep -cE "\bw[1-5]\b")
[ "$n" = "5" ] && [ "$w" = "5" ] && [ "$fails" = "0" ] && ok "mixed concurrent add/edit/sync: none lost" || bad "mixed concurrent writers" "adds=$n sets=$w failed=$fails $(cat "$T"/m[xes]*.log | sort | uniq -c | head -3)"

# ---- sync absorbs both conflict shapes (03 §6) --------------------------------------------
export VAULT_FILE="$T/sy.vault"
v init --kdf-test-params >/dev/null 2>&1
v add --title Base >/dev/null 2>&1
cp -R "$VAULT_FILE" "$T/stage1.vault"
"$V" --vault "$T/stage1.vault" --password-env MPW add --title FromPerFile >/dev/null 2>&1
cp "$T/stage1.vault/vault.bin" "$VAULT_FILE/vault 2.bin"
cp -R "$VAULT_FILE" "$T/stage2.vault"; rm -f "$T/stage2.vault/vault 2.bin"
"$V" --vault "$T/stage2.vault" --password-env MPW add --title FromSibling >/dev/null 2>&1
mv "$T/stage2.vault" "$T/sy 2.vault"
v sync >"$T/o" 2>&1; rc=$?
v list >"$T/o2" 2>&1
if [ $rc -eq 0 ] && grep -q FromPerFile "$T/o2" && grep -q FromSibling "$T/o2"; then ok "sync absorbs per-file and sibling-package copies"; else bad "sync absorb" "rc=$rc $(cat "$T/o") $(cat "$T/o2")"; fi
if [ ! -e "$VAULT_FILE/vault 2.bin" ] && [ ! -e "$T/sy 2.vault" ] && ls "$VAULT_FILE/backups" | grep -q "^conflict-"; then ok "sync moves both copies into backups/"; else bad "sync move" "$(ls "$VAULT_FILE" "$VAULT_FILE/backups" "$T" | tr '\n' ' ')"; fi

# NFD-named sibling of an NFC-named package (03 §3/§6 normalisation-insensitive)
NFCP="$T/$(printf 'Caf\xc3\xa9').vault"
NFDS="$T/$(printf 'Cafe\xcc\x81') 2.vault"
"$V" --vault "$NFCP" --password-env MPW init --kdf-test-params >/dev/null 2>&1
cp -R "$NFCP" "$T/stage3.vault"
"$V" --vault "$T/stage3.vault" --password-env MPW add --title FromNfd >/dev/null 2>&1
mv "$T/stage3.vault" "$NFDS"
"$V" --vault "$NFCP" --password-env MPW sync >"$T/o" 2>&1; rc=$?
"$V" --vault "$NFCP" --password-env MPW list >"$T/o2" 2>&1
if [ $rc -eq 0 ] && grep -q FromNfd "$T/o2" && [ ! -e "$NFDS" ]; then ok "sync absorbs an NFD-spelt sibling package"; else bad "sync NFD sibling" "rc=$rc $(cat "$T/o") $(cat "$T/o2")"; fi

# a foreign vault named like a conflict copy is left alone (03 §6 step 1)
"$V" --vault "$T/foreign.vault" --password-env MPW init --kdf-test-params >/dev/null 2>&1
mv "$T/foreign.vault" "$T/sy 3.vault"
v sync >"$T/o" 2>&1; rc=$?
[ -e "$T/sy 3.vault/vault.bin" ] && ok "sync leaves a foreign 'sy 3.vault' untouched" || bad "sync foreign copy" "rc=$rc $(cat "$T/o")"

# a whole-package copy missing a referenced blob is merged but not moved (03 §6 step 4)
cp -R "$VAULT_FILE" "$T/stage4.vault"; rm -rf "$T/stage4.vault/backups"
echo "late" >"$T/late.txt"
"$V" --vault "$T/stage4.vault" --password-env MPW attach add Base "$T/late.txt" >/dev/null 2>&1
"$V" --vault "$T/stage4.vault" --password-env MPW add --title FromWaiting >/dev/null 2>&1
rm -f "$T/stage4.vault/attachments/"*.bin
mv "$T/stage4.vault" "$T/sy 4.vault"
v sync >"$T/o" 2>&1; rc=$?
v list >"$T/o2" 2>&1
if [ $rc -ne 101 ] && grep -q FromWaiting "$T/o2" && [ -e "$T/sy 4.vault" ]; then ok "sync merges a blob-waiting package but does not move it"; else bad "sync waiting package" "rc=$rc exists=$([ -e "$T/sy 4.vault" ] && echo y || echo n) $(cat "$T/o")"; fi

echo
echo "CLI checks: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
