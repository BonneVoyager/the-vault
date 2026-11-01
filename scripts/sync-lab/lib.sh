# sync-lab helpers. Sourced by scripts/sync-lab.sh. Bash 3.2 compatible (macOS /bin/bash).
# Expects: ROOT, HERE, V (path to the vault binary), RUNDIR (absolute, under scripts/sync-lab/tmp/).

LAB_PW_DEFAULT="tidy-Walrus-orbit-Velvet-42"
LAB_PW="$LAB_PW_DEFAULT"
SCN_FAILS=""
DELIVER_SEQ=0
LAST_MODE=""
LAST_SYNC=""
LAST_SRC_DIRTY=0
LAST_DST_DIRTY=0

# Remove a directory this script created. The target and the tmp root are both resolved with
# `pwd -P`, so `..` and symlinks cannot lead outside scripts/sync-lab/tmp/.
safe_rm() {
  local d="$1" real root
  root="$(cd "$ROOT/scripts/sync-lab/tmp" 2>/dev/null && pwd -P)" || return 1
  real="$(cd "$d" 2>/dev/null && pwd -P)" || { echo "safe_rm: '$d' is not a directory" >&2; return 1; }
  case "$real" in
    "$root"/?*) rm -rf "$real" ;;
    *) echo "safe_rm: refusing to remove '$d' (resolves to '$real')" >&2; return 1 ;;
  esac
}

dev_id() {
  case "$1" in
    A) echo aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa ;;
    B) echo bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb ;;
    C) echo cccccccc-cccc-4ccc-8ccc-cccccccccccc ;;
    *) echo "bad device $1" >&2; return 1 ;;
  esac
}

# Package path of device $1 inside the current scenario lab.
dpath() { echo "$LAB/$1/main.vault"; }

# vx DEV args...  Run the CLI as device DEV: own device id, own HOME, own package.
# VX_FILE overrides the package path (two devices working on one shared package).
vx() {
  local d="$1"
  shift
  HOME="$LAB/home-$d" VAULT_DEVICE_ID="$(dev_id "$d")" VAULT_FILE="${VX_FILE:-$(dpath "$d")}" \
    LABPW="$LAB_PW" VAULT_ITEM_PASSWORD=p0 "$V" --password-env LABPW "$@"
}

lab_begin() {
  LAB="$RUNDIR/$1"
  SCN_FAILS=""
  LAB_PW="$LAB_PW_DEFAULT"
  mkdir -p "$LAB/A" "$LAB/B" "$LAB/C" "$LAB/home-A" "$LAB/home-B" "$LAB/home-C" "$LAB/atts"
}

fail() { SCN_FAILS="$SCN_FAILS
     $1"; }

# Copy the synced parts of a package: vault.bin, attachments. Not .lock, not backups/.
# $3 = all | vault | blobs.  Files land via tmp + rename like a cloud client would.
copy_pkg() {
  local s="$1" d="$2" only="${3:-all}" f
  mkdir -p "$d/attachments"
  if [ "$only" != blobs ] && [ -f "$s/vault.bin" ]; then
    cp "$s/vault.bin" "$d/.lab-incoming.tmp" && mv -f "$d/.lab-incoming.tmp" "$d/vault.bin"
  fi
  if [ "$only" != vault ] && [ -d "$s/attachments" ]; then
    for f in "$s/attachments/"*; do
      [ -e "$f" ] && cp "$f" "$d/attachments/.lab-blob.tmp" && mv -f "$d/attachments/.lab-blob.tmp" "$d/attachments/$(basename "$f")"
    done
  fi
  return 0
}

# cloud_sync SRC DST [--delay ms] [--drop] [--only vault|blobs]
#   [--conflict sibling|inpackage|sibling-n|inpackage-n]
# Shapes: sibling = "main (A's conflicted copy …).vault", inpackage = "vault (A's conflicted copy …).bin",
# sibling-n = "main N.vault" (iCloud), inpackage-n = "vault N.bin" (03 §6 numbered forms).
cloud_sync() {
  local src="$1" dst="$2" delay=0 drop=0 conflict="" only=all stamp n
  shift 2
  while [ $# -gt 0 ]; do
    case "$1" in
      --delay) delay="$2"; shift ;;
      --drop) drop=1 ;;
      --conflict) conflict="$2"; shift ;;
      --only) only="$2"; shift ;;
      *) echo "cloud_sync: bad option $1" >&2; return 2 ;;
    esac
    shift
  done
  if [ "$delay" -gt 0 ]; then sleep "$(awk -v ms="$delay" 'BEGIN{printf "%.3f", ms/1000}')"; fi
  if [ "$drop" = 1 ]; then return 0; fi
  DELIVER_SEQ=$((DELIVER_SEQ + 1))
  n=$((DELIVER_SEQ + 1)) # numbered forms start at 2 and never repeat
  stamp="2026-10-31 12-00-00 $DELIVER_SEQ"
  case "$conflict" in
    "") copy_pkg "$(dpath "$src")" "$(dpath "$dst")" "$only" ;;
    sibling) copy_pkg "$(dpath "$src")" "$LAB/$dst/main ($src's conflicted copy $stamp).vault" "$only" ;;
    sibling-n) copy_pkg "$(dpath "$src")" "$LAB/$dst/main $n.vault" "$only" ;;
    inpackage | inpackage-n)
      # Dropbox-style: the files inside the package sync one by one; vault.bin collides.
      if [ "$only" != vault ]; then copy_pkg "$(dpath "$src")" "$(dpath "$dst")" blobs; fi
      if [ "$conflict" = inpackage ]; then
        cp "$(dpath "$src")/vault.bin" "$(dpath "$dst")/vault ($src's conflicted copy $stamp).bin"
      else
        cp "$(dpath "$src")/vault.bin" "$(dpath "$dst")/vault $n.bin"
      fi
      ;;
    *) echo "cloud_sync: bad --conflict $conflict" >&2; return 2 ;;
  esac
}

# raw_view DEV FILE: everything the CLI shows for DEV, in sections. Errors become ERROR markers,
# attachments are decrypted and hashed, and every blob file is hashed.
raw_view() {
  local d="$1" out="$2" t id
  {
    echo "=== list"
    vx "$d" list 2>&1 || echo "=== ERROR list"
    echo "=== fav"
    vx "$d" list --favorites 2>&1 || echo "=== ERROR fav"
    for t in $(vx "$d" list 2>/dev/null | awk '{print $2}'); do
      echo "=== item $t"
      vx "$d" get "$t" --ids --reveal 2>&1 || echo "=== ERROR get $t"
      echo "=== att $t"
      vx "$d" attach list "$t" 2>&1 || echo "=== ERROR att $t"
      for id in $(vx "$d" attach list "$t" 2>/dev/null | awk '{print $1}'); do
        if vx "$d" attach get "$t" "$id" "$LAB/dec.tmp" >/dev/null 2>&1; then
          echo "=== sha $id $(shasum -a 256 "$LAB/dec.tmp" | awk '{print $1}')"
          rm -f "$LAB/dec.tmp"
        else
          echo "=== sha $id missing"
        fi
        echo "=== blob $id $(shasum -a 256 "$(dpath "$d")/attachments/$(echo "$id" | tr -d '-').bin" 2>/dev/null | awk '{print $1}')"
      done
    done
  } >"$out"
}

titles() { vx "$1" list 2>/dev/null | awk '{print $2}' | sort | tr '\n' ' '; }

expect_eq() { # expect_eq got want what
  [ "$1" = "$2" ] || fail "$3: got '$1', want '$2'"
}

# same_view X Y what: the CLI shows the same items, fields, favorites, attachments and blob bytes on
# both devices. A CLI error on either side is a failure, never "equal".
same_view() {
  local ra="$LAB/rawview-$1" rb="$LAB/rawview-$2"
  raw_view "$1" "$ra"
  raw_view "$2" "$rb"
  if grep -q '^=== ERROR' "$ra" "$rb"; then
    fail "$3: the CLI failed: $(grep -h '^=== ERROR' "$ra" "$rb" | head -2 | tr '\n' ' ')"
    return 0
  fi
  if grep -q '^=== sha .* missing$' "$ra" "$rb"; then
    fail "$3: an attachment cannot be read on one side: $(grep -h '^=== sha .* missing$' "$ra" "$rb" | head -1)"
  fi
  cmp -s "$ra" "$rb" || fail "$3: $1 and $2 differ:
$(diff "$ra" "$rb" | head -8)"
}

same_bytes() { # same_bytes X Y what
  cmp -s "$(dpath "$1")/vault.bin" "$(dpath "$2")/vault.bin" || fail "$3: vault.bin differs between $1 and $2"
}

fmt_version() { xxd -s 4 -l 2 -p "$1/vault.bin"; }

new_vault() { # new_vault DEV: init a fresh vault on DEV
  local o
  o="$(vx "$1" init --kdf-test-params 2>&1)" || fail "init on $1: $o"
}

# ---- cloud versions: who may plain-overwrite whom ---------------------------------------------
# The cloud holds one version counter per package. A device records the version it last took part
# in (.base-X) and the hash of its vault.bin at the last moment it matched the cloud (.rec-X).
fhash() { shasum "$(dpath "$1")/vault.bin" 2>/dev/null | awk '{print $1}'; }
cv_get() { cat "$LAB/.cloudver" 2>/dev/null || echo 0; }
base_get() { cat "$LAB/.base-$1" 2>/dev/null || echo 0; }
is_dirty() { [ "$(fhash "$1")" != "$(cat "$LAB/.rec-$1" 2>/dev/null)" ]; }
has_pkg() { [ -f "$(dpath "$1")/vault.bin" ]; }

# deliver SRC DST [cloud_sync options]: the fake cloud delivers SRC's package to DST, then DST runs
# `vault sync`. SRC first uploads (a new cloud version) if it holds the current version and changed.
# The delivery is a plain overwrite only if DST has no package, or SRC holds the current version and
# DST has no unsynced edits (a receiver that is merely behind is fast-forwarded). Otherwise (stale
# sender, or a receiver with edits the cloud has not seen) it is a conflict copy; --conflict forces one. Sets LAST_MODE (plain | conflict | dropped), LAST_SYNC.
deliver() {
  local src="$1" dst="$2" opts="$*" shape="" out dropped=0 v0 head=0 forced=0
  shift 2
  case " $* " in *" --drop "*) dropped=1 ;; esac
  case " $* " in *" --conflict "*) forced=1 ;; esac
  LAST_MODE=dropped
  LAST_SRC_DIRTY=0 LAST_DST_DIRTY=0
  [ "$dropped" = 1 ] && { cloud_sync "$src" "$dst" "$@"; return 0; }
  v0="$(cv_get)"
  LAST_SRC_DIRTY=0 LAST_DST_DIRTY=0
  is_dirty "$src" && LAST_SRC_DIRTY=1
  has_pkg "$dst" && is_dirty "$dst" && LAST_DST_DIRTY=1
  [ "$(base_get "$src")" = "$v0" ] && head=1
  if [ "$head" = 1 ] && is_dirty "$src"; then
    echo $((v0 + 1)) >"$LAB/.cloudver"
    echo $((v0 + 1)) >"$LAB/.base-$src"
    fhash "$src" >"$LAB/.rec-$src"
  fi
  if [ "$forced" = 0 ]; then
    if has_pkg "$dst" && ! { [ "$head" = 1 ] && ! is_dirty "$dst"; }; then
      case $((DELIVER_SEQ % 4)) in 0) shape=sibling ;; 1) shape=inpackage ;; 2) shape=sibling-n ;; *) shape=inpackage-n ;; esac
      set -- "$@" --conflict "$shape"
    fi
  fi
  cloud_sync "$src" "$dst" "$@" || { fail "cloud_sync $src->$dst failed"; return 0; }
  case " $* " in
    *" --conflict "*)
      LAST_MODE=conflict
      [ "$head" = 1 ] && cv_get >"$LAB/.base-$dst"
      ;;
    *)
      LAST_MODE=plain
      fhash "$dst" >"$LAB/.rec-$dst"
      base_get "$src" >"$LAB/.base-$dst"
      ;;
  esac
  out="$(vx "$dst" sync 2>&1)" || fail "vault sync on $dst after $opts failed: $(echo "$out" | tail -2 | tr '\n' ' ')"
  LAST_SYNC="$out"
}

# exchange X Y: two full rounds (X->Y, Y->X, X->Y, Y->X).
exchange() { deliver "$1" "$2"; deliver "$2" "$1"; deliver "$1" "$2"; deliver "$2" "$1"; }

ed() { # ed DEV ITEM edit-args...
  local d="$1" it="$2" o
  shift 2
  o="$(vx "$d" edit "$it" "$@" 2>&1)" || fail "edit on $d '$it' $*: $o"
  sleep 0.06
}

mk_item() { # mk_item DEV TITLE
  vx "$1" add --title "$2" --username u0 --password-field --url http://u0 --notes n0 >/dev/null 2>&1 || fail "add $2 on $1"
}

fid() { vx "$1" get "$2" --ids 2>/dev/null | awk -v n="$3:" '$1==n' | sed -E 's/.*\(id ([0-9a-f-]+)\).*/\1/' | head -1; }
fval() { vx "$1" get "$2" --ids --reveal 2>/dev/null | awk -v n="$3:" '$1==n' | sed -E 's/^[^:]*: (.*)  \(id [0-9a-f-]+\)$/\1/' | head -1; }

# ---- model-driven operations (model.py) ----------------------------------------------------------
m() { python3 -I "$HERE/model.py" "$LAB/model.json" "$@"; }
m_init() { m init; }

variant_opts() { # variant -> cloud_sync options
  case "$1" in
    plain) echo "" ;;
    drop) echo "--drop" ;;
    vault) echo "--only vault" ;;
    delay:*) echo "--delay ${1#delay:}" ;;
    forced:*) echo "--conflict ${1#forced:}" ;;
    *) echo "bad variant $1" >&2; return 1 ;;
  esac
}

# exec_op WORDS...: perform one model operation on the CLI (the model applies it separately).
exec_op() {
  local k="$1" d="$2" t="$3" x prev="" a=() id f
  case "$k" in
    add) mk_item "$d" "$t" ;;
    rm) vx "$d" rm "$t" >/dev/null 2>&1 || fail "rm '$t' on $d failed" ;;
    edit)
      shift 3
      for x in "$@"; do
        if [ "$prev" = --rm-field ] && ! [[ "$x" =~ ^[0-9a-f-]{36}$ ]]; then
          f="$(fid "$d" "$t" "$x")"
          [ -n "$f" ] || fail "no field '$x' on '$t' at $d for rm-field"
          a+=("$f")
        else
          a+=("$x")
        fi
        prev="$x"
      done
      ed "$d" "$t" "${a[@]}"
      ;;
    attach_add)
      head -c "$5" /dev/urandom >"$LAB/atts/$4"
      vx "$d" attach add "$t" "$LAB/atts/$4" >/dev/null 2>&1 || fail "attach add '$t' on $d failed"
      m sha "$4" "$(shasum -a 256 "$LAB/atts/$4" | awk '{print $1}')"
      ;;
    attach_rm)
      id="$(vx "$d" attach list "$t" 2>/dev/null | awk -v n="$4" '$2==n{print $1}' | head -1)"
      [ -n "$id" ] || { fail "no attachment '$4' on '$t' at $d"; return 0; }
      vx "$d" attach rm "$t" "$id" >/dev/null 2>&1 || fail "attach rm '$t' on $d failed"
      ;;
    *) fail "exec_op: unknown op $k" ;;
  esac
}

# mop WORDS...: apply an operation to the model, then run it on the CLI.
mop() { m apply "$@" && exec_op "$@"; }

# mdeliver SRC DST [variant]: deliver and tell the model; the model cross-checks the cloud rule.
mdeliver() {
  local src="$1" dst="$2" variant="${3:-plain}" o opts
  opts="$(variant_opts "$variant")" || return 1
  # shellcheck disable=SC2086
  deliver "$src" "$dst" $opts
  o="$(m delivered "$src" "$dst" "$variant" "$LAST_MODE" "$LAST_SRC_DIRTY" "$LAST_DST_DIRTY")"
  [ -z "$o" ] || fail "$o"
}
mexchange() { mdeliver "$1" "$2"; mdeliver "$2" "$1"; mdeliver "$1" "$2"; mdeliver "$2" "$1"; }

# mcheck DEV...: each device matches the model and the others; all vault.bin bytes equal if --bytes.
mcheck() {
  local d bytes=0 specs="" o first=""
  if [ "$1" = --bytes ]; then bytes=1; shift; fi
  for d in "$@"; do
    raw_view "$d" "$LAB/raw-$d"
    specs="$specs $d:$LAB/raw-$d"
    if [ -z "$first" ]; then first="$d"; elif [ "$bytes" = 1 ]; then same_bytes "$first" "$d" "byte equality"; fi
  done
  # shellcheck disable=SC2086
  o="$(m check $specs)" || fail "model check: $o"
}
