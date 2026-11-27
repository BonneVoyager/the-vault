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
# `init --kdf-test-params` is gated behind this since security review 2026-11-26 L-20.
export VAULT_DEV_KDF=1
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
n=$(v get "Site 2" --reveal 2>/dev/null | grep -cE "^c([0-9]|10):")
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

# ---- 2026-11-06: review fixes (D-1 symlinks, D-5 sanitize_line, D-10 caps, D-11 sync drain) ----
export VAULT_FILE="$T/rv.vault"
v init --kdf-test-params >/dev/null 2>&1
ESC=$(printf '\033'); BEL=$(printf '\007'); CR=$(printf '\r')
EVIL_T="Evil${ESC}[31mRED${ESC}]0;pwned${BEL}${CR}Fake"
EVIL_TAG="t${ESC}[2J"
v add --title "$EVIL_T" --tag "$EVIL_TAG" >"$T/o" 2>&1 || bad "add title with control chars" "$(cat "$T/o")"
EVIL_ID="$EVIL_T"
v edit "$EVIL_ID" --add "text:n${ESC}[1m=v${ESC}[5m${BEL}" >"$T/o" 2>&1 || echo "INFO edit add evil field: $(cat "$T/o")"
printf 'x' >"$T/a${ESC}[7m.txt"
v attach add "$EVIL_ID" "$T/a${ESC}[7m.txt" >"$T/o" 2>&1 || echo "INFO attach add evil name: $(cat "$T/o")"
san() { local label="$1"; shift; v "$@" >"$T/o" 2>&1
  if LC_ALL=C grep -q "[$ESC$BEL$CR]" "$T/o"; then bad "sanitize: '$label' prints raw control characters" "$(LC_ALL=C od -c "$T/o" | grep -m2 '033\|007\|\\r')"; else ok "sanitize: '$label' has no raw ESC/BEL/CR"; fi; }
san "list" list
san "get" get "$EVIL_ID"
san "get --reveal" get "$EVIL_ID" --reveal
san "get --ids" get "$EVIL_ID" --ids
san "attach list" attach list "$EVIL_ID"
san "list --tag" list --tag "$EVIL_TAG"
san "export to stdout?" export --yes --out "$T/evil.csv"
v get "nope${ESC}]0;x${BEL}" >"$T/o" 2>&1
LC_ALL=C grep -q "[$ESC$BEL]" "$T/o" && bad "sanitize: not-found error echoes control characters" "$(od -c "$T/o" | head -3)" || ok "sanitize: not-found error"
# a newline in a title must not forge an extra list row
NL_T="$(printf 'Line1\nFORGED-ROW')"
v add --title "$NL_T" >/dev/null 2>&1
v list >"$T/o" 2>&1
grep -q "^FORGED-ROW" "$T/o" && bad "sanitize: newline in title forges a list row" "$(cat "$T/o")" || ok "sanitize: newline in title stays on its row"

# vault sync drains more than 8 per-file conflict copies in one invocation (03 §2 D-11)
cp -R "$VAULT_FILE" "$T/rvbase.vault"
for i in $(seq 2 21); do
  rm -rf "$T/st.vault"; cp -R "$T/rvbase.vault" "$T/st.vault"
  "$V" --vault "$T/st.vault" --password-env MPW add --title "drain$i" >/dev/null 2>&1
  cp "$T/st.vault/vault.bin" "$VAULT_FILE/vault $i.bin"
done
v sync >"$T/o" 2>&1; rc=$?
n=$(v list 2>/dev/null | grep -c "drain[0-9]")
left=$(ls "$VAULT_FILE" | grep -c "^vault [0-9]*\.bin$")
[ $rc -eq 0 ] && [ "$n" = "20" ] && [ "$left" = "0" ] && ok "one 'vault sync' absorbs 20 per-file copies" || bad "sync drain of 20 copies" "rc=$rc merged=$n left=$left $(tail -3 "$T/o")"

# 70 MB attachment: the 64 MiB read caps must not reject a legitimate attachment (01 §4: 100 MB)
v add --title Big >/dev/null 2>&1
head -c 70000000 /dev/urandom >"$T/big.bin"
v attach add Big "$T/big.bin" >"$T/o" 2>&1 && ok "attach add 70 MB" || bad "attach add 70 MB" "$(cat "$T/o")"
bid=$(v attach list Big 2>/dev/null | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
v attach get Big "$bid" "$T/big.out" >"$T/o" 2>&1
cmp -s "$T/big.bin" "$T/big.out" && ok "attach get 70 MB round trip" || bad "attach get 70 MB" "$(cat "$T/o")"
rm -f "$T/big.bin" "$T/big.out"

# symlinked .lock: refused, not degraded to the no-lock path (03 §2 D-1)
rm -f "$VAULT_FILE/.lock"; ln -s "$T/lock-target" "$VAULT_FILE/.lock"
cp "$VAULT_FILE/vault.bin" "$T/lk-before.bin"
v add --title ViaLink >"$T/o" 2>&1; rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 101 ] && cmp -s "$T/lk-before.bin" "$VAULT_FILE/vault.bin" && [ ! -e "$T/lock-target" ]; then ok "symlinked .lock refused, nothing written"; else bad "symlinked .lock" "rc=$rc target-exists=$([ -e "$T/lock-target" ] && echo y || echo n) $(cat "$T/o")"; fi
rm -f "$VAULT_FILE/.lock"

# rm puts the item in the trash; the CLI cannot see it but the content is kept (02 delete)
v add --title TrashMe >/dev/null 2>&1
v rm TrashMe >"$T/o" 2>&1 && ok "rm into trash" || bad "rm" "$(cat "$T/o")"
v list >"$T/o" 2>&1
grep -q TrashMe "$T/o" && bad "rm: item still listed" || ok "rm: item hidden from list"

# ---- 2026-11-08: field icons (01 §4 Field.icon; 05 §2.3 "no CLI flag", not exported) ---------
FI="$ROOT/qa/spec-checks/target/debug/field_icons"
FPW="correct horse battery staple"
if [ ! -x "$FI" ]; then (cd "$ROOT/qa/spec-checks" && cargo build -q --bin field_icons) ; fi
mkdir -p "$T/fi.vault"; cp "$ROOT/crates/vault-core/tests/fixtures/v2-field-icon.vault" "$T/fi.vault/vault.bin"
fv() { FPW="$FPW" "$V" --vault "$T/fi.vault" --password-env FPW "$@"; }
"$FI" "$T/fi.vault/vault.bin" "$FPW" | cut -f2- | sort >"$T/fi-before"
grep -q "	key$" "$T/fi-before" && ok "fixture v2-field-icon carries icon key" || bad "fixture icon" "$(cat "$T/fi-before")"
FT=$(fv list 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*//; s/[[:space:]]{2,}.*$//')
fv get "$FT" >"$T/o" 2>&1 && ok "get on field-icon item" || bad "get field-icon item" "$(cat "$T/o")"
fv get "$FT" --reveal --ids >"$T/o" 2>&1 && ok "get --reveal --ids on field-icon item" || bad "get --reveal field-icon" "$(cat "$T/o")"
fv edit "$FT" --tag qa-fi >"$T/o" 2>&1 && ok "edit --tag on field-icon item" || bad "edit field-icon item" "$(cat "$T/o")"
"$FI" "$T/fi.vault/vault.bin" "$FPW" | cut -f2- | sort >"$T/fi-after"
cmp -s "$T/fi-before" "$T/fi-after" && ok "CLI edit keeps every field icon" || bad "CLI edit lost icons" "$(diff "$T/fi-before" "$T/fi-after")"
fv export --out "$T/fi.csv" --yes >"$T/o" 2>&1
# (the fixture's notes text itself contains the word "icon"; look for the icon value "key" as a cell)
if [ -f "$T/fi.csv" ] && ! grep -qE '(^|,)key(,|$)' "$T/fi.csv"; then ok "export CSV carries no field icon"; else bad "export field icon" "$(head -3 "$T/fi.csv" 2>/dev/null) $(cat "$T/o")"; fi
rm -f "$T/fi.csv"
# concurrent CLI writers on a vault with field icons (03 §2 V-02 lock; 03 §5 fields merge by id):
# 6 processes add new fields to other items and 6 add new fields to the icon item itself.
# (Concurrent `edit --tag` on one item keeps one tag: tags are one LWW list per 03 §5; see report Notes.)
for i in 1 2 3 4 5 6; do fv add --title "fic$i" >/dev/null 2>&1; done
pids=(); for i in 1 2 3 4 5 6; do fv edit "fic$i" --set "note$i=v$i" >"$T/fic$i.log" 2>&1 & pids+=($!); fv edit "$FT" --set "same$i=w$i" >"$T/fit$i.log" 2>&1 & pids+=($!); done
fails=0; for p in "${pids[@]}"; do wait "$p" || fails=$((fails+1)); done
"$FI" "$T/fi.vault/vault.bin" "$FPW" | cut -f2- | sort >"$T/fi-cc"
got=$(grep -c "^note[1-6]	-$" "$T/fi-cc")
same=$(grep -c "^same[1-6]	-$" "$T/fi-cc")
if [ "$fails" = 0 ] && [ "$got" = 6 ] && [ "$same" = 6 ] && grep -q "	key$" "$T/fi-cc"; then ok "12 concurrent CLI field adds on a field-icon vault: nothing lost, icons intact"; else bad "concurrent edits field-icon" "fails=$fails other-items=$got same-item=$same" "$(cat "$T"/fic*.log "$T"/fit*.log | sort | uniq -c | head -4)"; fi

# ---- 2026-11-15: concurrent CLI edits of one item (03 §5), Help page vs keymap (05 §2.5, §4) ----
export VAULT_FILE="$T/ca.vault"
v init --kdf-test-params >/dev/null 2>&1
export CA_SECRET="ca-Secret-Value-551"
cafail=0
for rep in 1 2 3; do
  CID=$(v add --title "Item$rep" --username u0 --url https://e.x --tag base 2>/dev/null | grep -oE '^[0-9a-f-]{36}$' | head -1)
  # C2 (03 §5 "Edits to different fields or items survive"; 01 §4 per-attribute stamps): six
  # processes edit six different attributes/fields of one item at once; all must survive.
  pids=()
  v edit "$CID" --title "Renamed$rep" >"$T/ca1" 2>&1 & pids+=($!)
  v edit "$CID" --favorite >"$T/ca2" 2>&1 & pids+=($!)
  v edit "$CID" --tag solo >"$T/ca3" 2>&1 & pids+=($!)
  v edit "$CID" --set "username=user$rep" >"$T/ca4" 2>&1 & pids+=($!)
  v edit "$CID" --set-env password=CA_SECRET >"$T/ca5" 2>&1 & pids+=($!)
  v edit "$CID" --icon "symbol:Star" >"$T/ca6" 2>&1 & pids+=($!)
  fails=0; for p in "${pids[@]}"; do wait "$p" || fails=$((fails+1)); done
  v get "$CID" --reveal >"$T/o" 2>&1
  miss=""
  grep -q "^title: Renamed$rep$" "$T/o" || miss="$miss title"
  grep -q "solo" "$T/o" || miss="$miss tag"
  grep -q "^username: user$rep" "$T/o" || miss="$miss username"
  grep -q "^password: $CA_SECRET" "$T/o" || miss="$miss password"
  if [ "$fails" != 0 ] || [ -n "$miss" ]; then cafail=1; bad "C2 rep $rep: concurrent edits of different attributes" "failed=$fails lost:$miss" "$(cat "$T"/ca[1-6] | sort | uniq -c | head -3)"; fi
  grep -q "$CA_SECRET" "$T"/ca[1-6] && { cafail=1; bad "C2: --set-env secret echoed"; }
done
[ $cafail = 0 ] && ok "concurrent edits of 6 different attributes on one item: none lost (3 reps)"
# C1: same attribute in parallel: every process reports success, at least one tag survives
CID=$(v add --title Tagged --tag base 2>/dev/null | grep -oE '^[0-9a-f-]{36}$' | head -1)
pids=(); for i in 1 2 3 4 5 6; do v edit "$CID" --tag "t$i" >"$T/ct$i" 2>&1 & pids+=($!); done
fails=0; for p in "${pids[@]}"; do wait "$p" || fails=$((fails+1)); done
v get "$CID" >"$T/o" 2>&1
n=$(grep '^tags:' "$T/o" | grep -oE '\bt[1-6]\b' | wc -l | tr -d ' ')
if [ "$fails" = 0 ] && [ "$n" -ge 1 ] && grep -q '^tags:.*base' "$T/o"; then ok "C1 concurrent --tag: all succeed, $n of 6 tags survive (spec: greater stamp wins)"; else bad "C1 concurrent --tag" "failed=$fails survivors=$n $(grep '^tags' "$T/o")"; fi

# 05 §2.5 Help: docs/help.md is the bundled page. Every shortcut in its table must be one the
# keymap in 05 §4 lists (a stale shortcut in Help misleads users), and none of the removed
# ⌘1/⌘2 pane-focus keys may be described as such.
HELP="$ROOT/docs/help.md"; SPEC5="$ROOT/specs/05-ui.md"
stale=""
while IFS= read -r keys; do
  for k in $(echo "$keys" | sed 's#/# #g; s#…# #g'); do
    case "$k" in ⌘1|⌘9) continue;; esac
    grep -qF -- "| $k" "$SPEC5" || grep -qF -- "$k " "$SPEC5" || grep -qF -- "$k |" "$SPEC5" || grep -qF -- "/ $k" "$SPEC5" || stale="$stale $k"
  done
done < <(awk -F'|' '/^\| / && NR>1 {print $3}' "$HELP" | grep -v -- '---' | grep -v '^ *Keys *$')
[ -z "$stale" ] && ok "help.md shortcuts all appear in 05 §4 keymap" || bad "help.md lists shortcuts not in 05 §4" "$stale"
grep -qiE "⌘1.*(list|item list)|⌘2.*detail" "$HELP" && bad "help.md describes removed ⌘1/⌘2 pane keys" || ok "help.md has no removed ⌘1/⌘2 pane keys"

# ---- 2026-11-17: save-lock wait (03 §2), --icon identifiers (01 §4, 05 §2.3 icon search) ----
export VAULT_FILE="$T/lk.vault"
v init --kdf-test-params >/dev/null 2>&1
v add --title Seed >/dev/null 2>&1
# 03 §2 "The lock wait is 10 s (`SaveLockTimeout`, nothing written) ... production code has no override."
perl -MFcntl=:flock -e '$|=1; open(my $f, ">>", $ARGV[0]) or die; flock($f, LOCK_EX) or die; print "locked\n"; sleep 60' "$VAULT_FILE/.lock" >"$T/perl.out" &
PERLPID=$!
for _ in $(seq 1 50); do grep -q locked "$T/perl.out" 2>/dev/null && break; sleep 0.1; done
before=$(shasum "$VAULT_FILE/vault.bin")
s0=$(date +%s)
VAULT_LOCK_TIMEOUT_MS=1 VAULT_LOCK_TIMEOUT=0 v add --title Blocked >"$T/o" 2>&1; rc=$?
el=$(( $(date +%s) - s0 ))
kill $PERLPID 2>/dev/null; wait $PERLPID 2>/dev/null
after=$(shasum "$VAULT_FILE/vault.bin")
if [ $rc -ne 0 ] && [ $el -ge 9 ] && [ $el -le 20 ] && [ "$before" = "$after" ] && ! ls -a "$VAULT_FILE" | grep -q '\.tmp'; then ok "held .lock: add waits ~10 s ($el s), fails, writes nothing; env vars do not shorten it"; else bad "held .lock" "rc=$rc elapsed=${el}s same=$([ "$before" = "$after" ] && echo y || echo n)" "$(cat "$T/o")"; fi
grep -q "$MPW" "$T/o" && bad "lock timeout message echoes the master password" || ok "lock timeout message carries no master password"
v add --title Unblocked >"$T/o" 2>&1 && ok "add succeeds once the lock is released" || bad "add after lock release" "$(cat "$T/o")"
# --icon symbol:<any identifier> (01 §4 any Lucide identifier; 05 §2.3 CLI accepts any #RRGGBB)
II="$ROOT/qa/spec-checks/target/debug/item_icons"
if [ ! -x "$II" ]; then (cd "$ROOT/qa/spec-checks" && cargo build -q --bin item_icons); fi
icfail=""
for spec in "symbol:a-arrow-down|value=\"a-arrow-down\"" "symbol:AArrowDown:#abcdef|color=\"#abcdef\"" "symbol:NotInCatalog|value=\"NotInCatalog\"" "symbol:../x|value=\"../x\""; do
  arg="${spec%%|*}"; want="${spec#*|}"
  v edit Seed --icon "$arg" >"$T/o" 2>&1 || icfail="$icfail [$arg rc]"
  "$II" "$VAULT_FILE/vault.bin" "$MPW" | grep '^"Seed"' | grep -qF "$want" || icfail="$icfail [$arg stored: $("$II" "$VAULT_FILE/vault.bin" "$MPW" | grep '^"Seed"')]"
done
[ -z "$icfail" ] && ok "--icon symbol:<identifier> stored verbatim (kebab, Pascal, unknown, lowercase colour)" || bad "--icon identifiers" "$icfail"
v edit Seed --icon "symbol:$(printf 'E\033[2J\007x')" >/dev/null 2>&1
v get Seed >"$T/o" 2>&1; rc=$?
if [ $rc = 0 ] && ! LC_ALL=C grep -q $'\033' "$T/o" && ! LC_ALL=C grep -q $'\007' "$T/o"; then ok "get sanitises control bytes in an icon value"; else bad "get prints raw control bytes from icon" "$(od -c "$T/o" | head -5)"; fi
# six concurrent --icon edits of one item: all succeed, exactly one icon survives (03 §5 same attribute)
pids=(); for i in 1 2 3 4 5 6; do v edit Seed --icon "symbol:c-$i" >"$T/ic$i" 2>&1 & pids+=($!); done
fails=0; for p in "${pids[@]}"; do wait "$p" || fails=$((fails+1)); done
cur=$("$II" "$VAULT_FILE/vault.bin" "$MPW" | grep '^"Seed"')
if [ $fails = 0 ] && echo "$cur" | grep -qE 'value="c-[1-6]"'; then ok "6 concurrent --icon edits: all succeed, one survives"; else bad "concurrent --icon" "fails=$fails $cur"; fi

# ---- 2026-11-21: realigned spec sentences (00 phase 1 `sync`, 03 §2 shared open lock, deps) ----
export VAULT_FILE="$T/r21.vault"
v init --kdf-test-params >/dev/null 2>&1
v add --title R21 >/dev/null 2>&1
# 00 phase 1 (aligned 2026-11-19): `sync` "save only if something changed"
h0=$(shasum "$VAULT_FILE/vault.bin"); m0=$(stat -f %m:%i "$VAULT_FILE/vault.bin")
sleep 1.1
v sync >"$T/o" 2>&1; rc=$?
h1=$(shasum "$VAULT_FILE/vault.bin"); m1=$(stat -f %m:%i "$VAULT_FILE/vault.bin")
if [ $rc = 0 ] && [ "$h0" = "$h1" ] && [ "$m0" = "$m1" ]; then ok "sync with nothing to do exits 0 and does not rewrite vault.bin"; else bad "no-op sync" "rc=$rc same-bytes=$([ "$h0" = "$h1" ] && echo y || echo n) same-mtime/inode=$([ "$m0" = "$m1" ] && echo y || echo n) $(cat "$T/o")"; fi
# An unparseable per-file copy: 03 §6 does not say what happens; record it (2026-11-21 Note), never deleted
head -c 3000 /dev/urandom >"$VAULT_FILE/vault 2.bin"
v sync >"$T/o" 2>&1; rc=$?
echo "INFO sync with an unparseable per-file copy: rc=$rc $(grep -v '^note: a different vault' "$T/o" | head -2 | tr '\n' ' ')"
if [ -e "$VAULT_FILE/vault 2.bin" ] || ls "$VAULT_FILE/backups" 2>/dev/null | grep -q 'vault 2'; then ok "unparseable conflict copy is never deleted"; else bad "unparseable conflict copy vanished" "$(ls "$VAULT_FILE" "$VAULT_FILE/backups")"; fi
rm -f "$VAULT_FILE/vault 2.bin"
# ... "fails with "not converged" if any problem was reported": a per-file copy that parses but fails to merge
python3 - "$VAULT_FILE/vault.bin" "$VAULT_FILE/vault 2.bin" <<'PY'
import sys
b = bytearray(open(sys.argv[1], 'rb').read())
hl = int.from_bytes(b[6:10], 'big'); i = b.index(b'bct', 10 + hl)
b[i + 40] ^= 1
open(sys.argv[2], 'wb').write(b)
PY
v sync >"$T/o" 2>&1; rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 101 ] && grep -qi "not converged" "$T/o"; then ok "sync with a copy that fails to merge exits non-zero with 'not converged'"; else bad "sync failing merge -> not converged" "rc=$rc $(head -3 "$T/o")"; fi
echo "INFO message for a per-file copy whose first item was altered: $(grep -v 'not converged\|^note:' "$T/o" | head -1 | sed "s|$T|<tmp>|")"
[ -e "$VAULT_FILE/vault 2.bin" ] && ok "unmergeable conflict copy kept in place" || bad "unmergeable conflict copy vanished" "$(ls "$VAULT_FILE")"
rm -f "$VAULT_FILE/vault 2.bin"
# a foreign sibling package: report what `sync` says (03 §6 step 1 ForeignVault; problem or not is unspecified)
OTHERF="$T/other-r21.vault"; "$V" --vault "$OTHERF" --password-env MPW init --kdf-test-params >/dev/null 2>&1
cp -R "$OTHERF" "$T/r21 2.vault"
v sync >"$T/o" 2>&1; rc=$?
echo "INFO sync with only a foreign sibling: rc=$rc $(head -2 "$T/o" | tr '\n' ' ')"
[ -e "$T/r21 2.vault/vault.bin" ] && ok "foreign sibling untouched by sync" || bad "foreign sibling touched" "$(ls "$T")"
rm -rf "$T/r21 2.vault" "$OTHERF"
# 03 §2 (aligned 2026-11-19): "`open` takes a shared lock around its read of `vault.bin`"
perl -e 'use Fcntl ":flock"; open(my $f, ">>", $ARGV[0]) or die; flock($f, LOCK_EX) or die; $|=1; print "L\n"; sleep 3;' "$VAULT_FILE/.lock" >"$T/perl.out" &
PERLPID=$!
for _ in $(seq 1 50); do grep -q L "$T/perl.out" 2>/dev/null && break; sleep 0.1; done
s0=$(perl -MTime::HiRes=time -e 'printf "%.2f", time')
v list >"$T/o" 2>&1; rc=$?
s1=$(perl -MTime::HiRes=time -e 'printf "%.2f", time')
wait $PERLPID 2>/dev/null
el=$(echo "$s1 - $s0" | bc)
if [ $rc = 0 ] && grep -q R21 "$T/o" && [ "$(echo "$el >= 2.0" | bc)" = 1 ]; then ok "list waits for a held exclusive save lock (${el}s), then reads"; else bad "open shared lock" "rc=$rc elapsed=${el}s $(head -2 "$T/o")"; fi
# 01 §1 version 0 through the CLI: an error, no panic; message recorded (05 §2.2 maps UnsupportedVersion to "newer version" in the app)
cp "$VAULT_FILE/vault.bin" "$T/v0.bin"
printf '\x00\x00' | dd of="$VAULT_FILE/vault.bin" bs=1 seek=4 conv=notrunc 2>/dev/null
v list >"$T/o" 2>&1; rc=$?
if [ $rc -ne 0 ] && [ $rc -ne 101 ]; then ok "CLI refuses a version-0 file without panicking"; else bad "CLI version-0 file" "rc=$rc $(cat "$T/o")"; fi
echo "INFO CLI message for a version-0 file: $(head -1 "$T/o")"
cp "$T/v0.bin" "$VAULT_FILE/vault.bin"
export VAULT_FILE="$T/main.vault"

# Dependency lists that the 2026-11-19 realignment states as "aligned to code" (02, 03, 04)
deps() { (cd "$ROOT" && cargo tree -q --offline -p "$1" -e "$2" --depth 1 --prefix none $3 2>/dev/null) | tail -n +2 | awk '{print $1}' | sort -u | tr '\n' ' '; }
cmp_deps() { # name edge flags "spec list"
  local got want miss extra
  got=$(deps "$1" "$2" "$3"); want=$(echo "$4" | tr ' ' '\n' | sort -u | tr '\n' ' ')
  miss=$(comm -23 <(echo "$want" | tr ' ' '\n' | sed '/^$/d') <(echo "$got" | tr ' ' '\n' | sed '/^$/d') | tr '\n' ' ')
  extra=$(comm -13 <(echo "$want" | tr ' ' '\n' | sed '/^$/d') <(echo "$got" | tr ' ' '\n' | sed '/^$/d') | tr '\n' ' ')
  if [ -z "$miss$extra" ]; then ok "$1 $2 dependencies match the spec list"; else bad "$1 $2 dependencies vs spec" "in code, not in spec: ${extra:-none}" "in spec, not in code: ${miss:-none}"; fi
}
cmp_deps vault-core normal "--features kdbx" "argon2 chacha20poly1305 hkdf sha2 rand zeroize secrecy ciborium serde uuid totp-rs unicode-normalization thiserror csv zip serde_json zxcvbn keepass"
cmp_deps vault-sync normal "" "vault-core notify notify-debouncer-full rustix blake3 crossbeam-channel rand unicode-normalization zeroize thiserror tracing"
(cd "$ROOT" && cargo tree -q --offline -p vault-sync -e dev --depth 1 --prefix none 2>/dev/null) | grep -q '^tempfile' && ok "vault-sync: tempfile is a dev dependency" || bad "vault-sync tempfile dev-only" "not found in dev edges"
# 04 line 5 as corrected 2026-11-21 (bug hunt L4)
cmp_deps vault-macos normal "" "vault-core thiserror uuid dirs tracing secrecy ciborium rqrr objc2 objc2-foundation objc2-app-kit objc2-local-authentication objc2-security objc2-core-foundation objc2-core-graphics objc2-service-management libc zeroize"

# User-facing help (bundled by include_str!, 05 §2.5 Help) vs the 2026-11-19 UI changes
HELP="$ROOT/docs/help.md"
if grep -n 'Move…\|Move\.\.\.' "$HELP" >"$T/o"; then bad "docs/help.md still mentions a Move… action (05 §2.5: no Move…, 2026-11-19)" "$(cat "$T/o")"; else ok "docs/help.md has no Move… action"; fi
grep -qi 'recently created' "$HELP" && echo "INFO help.md mentions Recently Created" || echo "INFO help.md does not mention the Recently Created sort"
grep -qi 'newer version' "$HELP" && echo "INFO help.md mentions the newer-version message" || echo "INFO help.md does not mention the newer-version message"
# Cross-spec: the removed Move… must not be described as present anywhere in specs/
grep -n 'Move…' "$ROOT"/specs/*.md | grep -v 'no "Move…"' >"$T/o"
[ -s "$T/o" ] && bad "a spec still describes Move…" "$(cat "$T/o")" || ok "no spec describes a Move… action"

# ---- 2026-11-21b: unreadable conflict copies (03 §6 step 1, §8 UnreadableConflict; 00 phase 1 `sync`) ----
# 03 §6 step 1 (2026-11-21): "if the candidate does not parse or carries an unsupported format version →
# emit SyncEvent::UnreadableConflict(path) once and leave it in place (`vault sync` reports it and exits
# "not converged" …)"; 00: `sync` "fails with "not converged" if any problem was reported".
export VAULT_FILE="$T/u21.vault"
v init --kdf-test-params >/dev/null 2>&1
v add --title U21 >/dev/null 2>&1
sync_rc() { v sync >"$T/o" 2>&1; echo $?; }
setver() { cp "$VAULT_FILE/vault.bin" "$2"; printf "$1" | dd of="$2" bs=1 seek=4 conv=notrunc 2>/dev/null; }
head -c 3000 /dev/urandom >"$T/g.bin"
cp "$T/g.bin" "$VAULT_FILE/vault 2.bin"
h0=$(shasum "$VAULT_FILE/vault.bin")
for run in 1 2; do
  rc=$(sync_rc)
  if [ "$rc" = 1 ] && grep -q "not converged" "$T/o" && grep -q "vault 2.bin" "$T/o"; then ok "sync with a random-bytes per-file copy: rc 1, names the copy, 'not converged' (run $run)"; else bad "unreadable per-file copy (run $run)" "rc=$rc $(sed "s|$T|<tmp>|g" "$T/o" | head -3 | tr '\n' ' ')"; fi
done
cmp -s "$T/g.bin" "$VAULT_FILE/vault 2.bin" && ok "unreadable copy left in place byte-identical" || bad "unreadable copy changed or moved" "$(ls "$VAULT_FILE")"
[ "$h0" = "$(shasum "$VAULT_FILE/vault.bin")" ] && ok "unreadable copy does not rewrite vault.bin" || bad "vault.bin rewritten by sync with only an unreadable copy"
grep -q "$MPW" "$T/o" && bad "sync output contains the master password" || ok "sync output does not contain the master password"
rm -f "$VAULT_FILE/vault 2.bin"
# 03 §8: "unsupported format version (any value, 0 included)"
for ver in '\x00\x00' '\x00\x03' '\xff\xff'; do
  setver "$ver" "$VAULT_FILE/vault 3.bin"; cp "$VAULT_FILE/vault 3.bin" "$T/vc.bin"
  rc=$(sync_rc)
  if [ "$rc" = 1 ] && grep -q "not converged" "$T/o" && cmp -s "$T/vc.bin" "$VAULT_FILE/vault 3.bin"; then ok "per-file copy with version $ver: not converged, kept"; else bad "per-file copy with version $ver" "rc=$rc $(sed "s|$T|<tmp>|g" "$T/o" | head -2 | tr '\n' ' ')"; fi
  rm -f "$VAULT_FILE/vault 3.bin"
done
# whole-package shape (03 §1 "Conflict copies come in two shapes")
mkdir -p "$T/u21 2.vault"; cp "$T/g.bin" "$T/u21 2.vault/vault.bin"
rc=$(sync_rc)
if [ "$rc" = 1 ] && grep -q "not converged" "$T/o" && grep -q "u21 2.vault" "$T/o" && cmp -s "$T/g.bin" "$T/u21 2.vault/vault.bin"; then ok "unreadable sibling package: not converged, named, kept"; else bad "unreadable sibling package" "rc=$rc $(sed "s|$T|<tmp>|g" "$T/o" | head -2 | tr '\n' ' ')"; fi
rm -rf "$T/u21 2.vault"
# a readable copy next to an unreadable one: the readable one is absorbed, the run still fails
cp -R "$VAULT_FILE" "$T/stage.vault"
"$V" --vault "$T/stage.vault" --password-env MPW add --title FromCopy21 >/dev/null 2>&1
cp "$T/stage.vault/vault.bin" "$VAULT_FILE/vault 4.bin"; rm -rf "$T/stage.vault"
cp "$T/g.bin" "$VAULT_FILE/vault 5.bin"
rc=$(sync_rc)
v list >"$T/o2" 2>&1
if [ "$rc" = 1 ] && grep -q "not converged" "$T/o" && grep -q FromCopy21 "$T/o2" && [ ! -e "$VAULT_FILE/vault 4.bin" ] && [ -e "$VAULT_FILE/vault 5.bin" ]; then ok "readable copy absorbed beside an unreadable one; run reports not converged"; else bad "readable + unreadable copies" "rc=$rc $(sed "s|$T|<tmp>|g" "$T/o" | head -3 | tr '\n' ' ') list: $(tr '\n' ' ' <"$T/o2")" "$(ls "$VAULT_FILE")"; fi
rm -f "$VAULT_FILE/vault 5.bin"
rc=$(sync_rc)
[ "$rc" = 0 ] && ok "sync exits 0 once the unreadable copy is gone" || bad "sync after removing the unreadable copy" "rc=$rc $(head -2 "$T/o")"
# 03 §2 watcher bounds: one-shot callers loop on poll() until 0 — 20 unreadable copies terminate
for k in $(seq 10 29); do head -c 400 /dev/urandom >"$VAULT_FILE/vault $k.bin"; done
s0=$(date +%s); rc=$(sync_rc); s1=$(date +%s)
n=$(grep -c "unreadable\|vault [0-9]*\.bin" "$T/o")
kept=$(ls "$VAULT_FILE" | grep -c '^vault [0-9]*\.bin$')
if [ "$rc" = 1 ] && [ "$kept" = 20 ] && [ $((s1-s0)) -lt 60 ]; then ok "sync with 20 unreadable copies terminates ($((s1-s0)) s), rc 1, all kept"; else bad "20 unreadable copies" "rc=$rc kept=$kept $((s1-s0)) s"; fi
[ "$n" -ge 20 ] && ok "each of 20 unreadable copies is named" || bad "20 unreadable copies named" "lines naming copies: $n"
# concurrent writers while an unreadable copy sits in the package (00: concurrent CLI use, 03 §2 lock)
for k in $(seq 10 29); do rm -f "$VAULT_FILE/vault $k.bin"; done
cp "$T/g.bin" "$VAULT_FILE/vault 2.bin"
pids=""
for k in 1 2 3 4; do (v add --title "Conc21-$k" >"$T/ca$k" 2>&1; echo $? >"$T/ca$k.rc") & pids="$pids $!"; done
for k in 1 2; do (v sync >"$T/cs$k" 2>&1; echo $? >"$T/cs$k.rc") & pids="$pids $!"; done
wait $pids
v list >"$T/o2" 2>&1
okc=1; for k in 1 2 3 4; do grep -q "Conc21-$k" "$T/o2" || okc=0; [ "$(cat "$T/ca$k.rc")" = 0 ] || okc=0; done
for k in 1 2; do [ "$(cat "$T/cs$k.rc")" = 1 ] || okc=0; done
if [ $okc = 1 ] && cmp -s "$T/g.bin" "$VAULT_FILE/vault 2.bin"; then ok "4 concurrent adds + 2 syncs with an unreadable copy: all adds kept, syncs rc 1, copy kept"; else bad "concurrent writers with an unreadable copy" "adds rc: $(cat "$T"/ca?.rc | tr '\n' ' ') syncs rc: $(cat "$T"/cs?.rc | tr '\n' ' ')" "$(tr '\n' ' ' <"$T/o2")"; fi
rm -f "$VAULT_FILE/vault 2.bin"
# 03 §2 D-1: "every file the package opens (… conflict-copy sources) is opened with O_NOFOLLOW and must be a
# regular file after fstat; a symlink or special file is `UnsafePackageEntry`, never a silent fallback"
ln -s "$VAULT_FILE/vault.bin" "$VAULT_FILE/vault 6.bin"
rc=$(sync_rc)
if [ "$rc" != 0 ] && [ "$rc" != 101 ]; then ok "symlinked per-file copy is reported (rc $rc)"; else bad "symlinked per-file conflict copy skipped silently (rc $rc): $(head -1 "$T/o")"; fi
rm -f "$VAULT_FILE/vault 6.bin"
mkfifo "$VAULT_FILE/vault 7.bin"
rc=$(sync_rc)
if [ "$rc" != 0 ] && [ "$rc" != 101 ]; then ok "FIFO per-file copy is reported (rc $rc)"; else bad "FIFO per-file conflict copy skipped silently (rc $rc): $(head -1 "$T/o")"; fi
rm -f "$VAULT_FILE/vault 7.bin"
mkdir -p "$T/u21-else"; cp -R "$VAULT_FILE" "$T/u21-else/c.vault"; ln -s "$T/u21-else/c.vault" "$T/u21 4.vault"
rc=$(sync_rc)
if [ "$rc" != 0 ] && [ "$rc" != 101 ]; then ok "symlinked sibling package is reported (rc $rc)"; else bad "symlinked sibling package skipped silently (rc $rc): $(head -1 "$T/o")"; fi
[ -e "$T/u21-else/c.vault/vault.bin" ] && ok "symlinked sibling package target untouched" || bad "symlinked sibling target moved"
rm -rf "$T/u21 4.vault" "$T/u21-else"
mkdir -p "$T/u21 3.vault"; ln -s "$VAULT_FILE/vault.bin" "$T/u21 3.vault/vault.bin"
rc=$(sync_rc)
if [ "$rc" != 0 ] && [ "$rc" != 101 ]; then ok "sibling package with a symlinked vault.bin is reported (rc $rc)"; else bad "sibling with symlinked vault.bin skipped silently (rc $rc)"; fi
rm -rf "$T/u21 3.vault"
mkfile -n 65m "$VAULT_FILE/vault 8.bin"
rc=$(sync_rc)
if [ "$rc" = 1 ] && [ -e "$VAULT_FILE/vault 8.bin" ]; then ok "65 MiB per-file copy: rc 1, kept"; else bad "oversize per-file copy" "rc=$rc $(head -1 "$T/o")"; fi
rm -f "$VAULT_FILE/vault 8.bin"
export VAULT_FILE="$T/main.vault"
# docs/help.md ⌥ line vs 05 §2.3 "TOTP secret is still never shown" (bug hunt 2026-11-21 N9)
grep -q 'Hold ⌥.*TOTP secret stays hidden' "$ROOT/docs/help.md" && ok "help.md: ⌥ keeps the TOTP secret hidden (05 §2.3)" || bad "help.md ⌥ sentence vs 05 §2.3" "$(grep -n '⌥' "$ROOT/docs/help.md")"
grep -n 'Hold ⌥' "$ROOT/README.md" | sed 's/^/INFO README: /'

# ---- 2026-11-22: special conflict entries, backups under concurrent writers (03 §2 D-1, §4, §6) ----
# 03 §6 step 1: "is not a regular file / directory (symlink, FIFO …) → emit SyncEvent::UnreadableConflict(path)
# once … and leave it in place (`vault sync` reports it and exits "not converged" …)"
export VAULT_FILE="$T/sp22.vault"
v init --kdf-test-params >/dev/null 2>&1
v add --title SP22 >/dev/null 2>&1
lim() { perl -e 'alarm shift; exec @ARGV' "$@"; }
sp_sync() { lim 60 "$V" --password-env MPW sync >"$T/o" 2>&1; echo $?; }
h0=$(shasum "$VAULT_FILE/vault.bin" | cut -d' ' -f1)
sp_case() { # $1 label, $2 path that must stay
  rc=$(sp_sync)
  if [ "$rc" = 142 ]; then bad "sync hangs on $1"; return; fi
  if [ "$rc" = 1 ] && grep -q "not converged" "$T/o" && [ -n "$(ls -d "$2" 2>/dev/null)$( [ -L "$2" ] && echo l)" ]; then ok "sync with $1: rc 1, not converged, left in place"; else bad "sync with $1" "rc=$rc $(sed "s|$T|<tmp>|g" "$T/o" | head -2 | tr '\n' ' ')"; fi
  [ "$h0" = "$(shasum "$VAULT_FILE/vault.bin" | cut -d' ' -f1)" ] || bad "vault.bin rewritten by sync with $1"
}
python3 -I -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$VAULT_FILE/vault 2.bin"
sp_case "a unix socket named vault 2.bin" "$VAULT_FILE/vault 2.bin"; rm -f "$VAULT_FILE/vault 2.bin"
mkdir "$VAULT_FILE/vault 2.bin"; cp "$VAULT_FILE/vault.bin" "$VAULT_FILE/vault 2.bin/vault.bin"
sp_case "a directory named vault 2.bin" "$VAULT_FILE/vault 2.bin"; rm -rf "$VAULT_FILE/vault 2.bin"
ln -s "$T/nowhere" "$VAULT_FILE/vault 2.bin"
sp_case "a dangling symlink vault 2.bin" "$VAULT_FILE/vault 2.bin"; rm -f "$VAULT_FILE/vault 2.bin"
ln -s /dev/zero "$VAULT_FILE/vault 2.bin"
sp_case "a symlink to /dev/zero" "$VAULT_FILE/vault 2.bin"; rm -f "$VAULT_FILE/vault 2.bin"
mkfifo "$T/sp22 2.vault"
sp_case "a FIFO sibling package" "$T/sp22 2.vault"; rm -f "$T/sp22 2.vault"
mkdir -p "$T/sp22 3.vault"; mkfifo "$T/sp22 3.vault/vault.bin"
sp_case "a sibling package whose vault.bin is a FIFO" "$T/sp22 3.vault/vault.bin"; rm -rf "$T/sp22 3.vault"
# 03 §6 names whole-package copies as directories; a plain file is recorded only (Note, not a check)
cp "$VAULT_FILE/vault.bin" "$T/sp22 4.vault"
rc=$(sp_sync); echo "INFO sync with a plain file named like a sibling package: rc $rc $(sed "s|$T|<tmp>|g" "$T/o" | grep -v 'different vault' | head -1)"; rm -f "$T/sp22 4.vault"
rc=$(sp_sync); [ "$rc" = 0 ] && ok "sync exits 0 after the special entries are gone" || bad "sync after cleanup" "rc=$rc $(head -2 "$T/o")"
# 03 §2 V-02 lock + §4 snapshots under 10 concurrent writers: every backup is "a complete,
# independently-openable vault file" (03 §1), no tmp file left behind, no item lost.
pids=""
for k in $(seq 1 10); do (v add --title "BK22-$k" >"$T/b$k" 2>&1; echo $? >"$T/b$k.rc") & pids="$pids $!"; done
wait $pids
v list >"$T/o2" 2>&1
okc=1; for k in $(seq 1 10); do grep -q "BK22-$k\$\|BK22-$k " "$T/o2" || okc=0; [ "$(cat "$T/b$k.rc")" = 0 ] || okc=0; done
[ $okc = 1 ] && ok "10 concurrent adds: all succeed and survive" || bad "10 concurrent adds" "rc: $(cat "$T"/b*.rc | tr '\n' ' ')" "$(tr '\n' ' ' <"$T/o2")"
ls -a "$VAULT_FILE" | grep -q '\.tmp-' && bad "tmp file left in the package" "$(ls -a "$VAULT_FILE")" || ok "no tmp file left after concurrent writers"
nb=0; nbad=0; badmode=""
for f in "$VAULT_FILE"/backups/*; do
  [ -f "$f" ] || continue; nb=$((nb+1))
  rm -rf "$T/bkopen.vault"; mkdir "$T/bkopen.vault"; cp "$f" "$T/bkopen.vault/vault.bin"
  "$V" --vault "$T/bkopen.vault" --password-env MPW list >/dev/null 2>&1 || nbad=$((nbad+1))
  m=$(stat -f %Lp "$f"); [ "$m" = 600 ] || badmode="$badmode $(basename "$f"):$m"
done
rm -rf "$T/bkopen.vault"
[ $nb -ge 1 ] && [ $nbad = 0 ] && ok "all $nb backups open with the master password" || bad "backups openable" "$nbad of $nb failed"
[ -z "$badmode" ] && ok "backup files are mode 0600" || bad "backup file modes (vault.bin is 0600)" "$badmode"
echo "INFO backups/ dir mode $(stat -f %Lp "$VAULT_FILE/backups"), package mode $(stat -f %Lp "$VAULT_FILE")"
# 03 §2 D-1 "`backups/` … must not be symlinks": a save never writes a snapshot through a symlinked backups/.
mkdir -p "$T/bk-elsewhere"; mv "$VAULT_FILE/backups" "$T/bk-real"; ln -s "$T/bk-elsewhere" "$VAULT_FILE/backups"
lim 60 "$V" --password-env MPW add --title ThroughLink >"$T/o" 2>&1; rc=$?
[ -z "$(ls -A "$T/bk-elsewhere")" ] && ok "no snapshot written through a symlinked backups/ (add rc $rc)" || bad "snapshot written through symlinked backups/" "$(ls "$T/bk-elsewhere")"
# each CLI process is a "first save after unlock" (03 §4), so this add attempts a snapshot; the library
# reports the refusal as an Error event (bk09); D-1 "never a silent fallback" — the CLI must pass it on
grep -qi "backup" "$T/o" && ok "add reports the refused snapshot through a symlinked backups/" || bad "add with a symlinked backups/ skips the policy snapshot silently (rc $rc)" "output: $(sed "s|$T|<tmp>|g" "$T/o" | tr '\n' ' ')"
rm -f "$VAULT_FILE/backups"; mv "$T/bk-real" "$VAULT_FILE/backups"; rm -rf "$T/bk-elsewhere"
export VAULT_FILE="$T/main.vault"

echo
echo "CLI checks: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
