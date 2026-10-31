#!/usr/bin/env bash
# Build the bundled brand-icon pack from Simple Icons (CC0 1.0).
# See --help. Never uses npm; downloads the GitHub tag tarball and verifies its SHA-256.
set -euo pipefail

SI_VERSION="16.35.0"
SI_SHA256="e9891585ab70f2f482bfa12f29a62db874899a2b74640227aee7921e4bee2ad0"
SI_URL="https://github.com/simple-icons/simple-icons/archive/refs/tags/${SI_VERSION}.tar.gz"

usage() {
  cat <<USAGE
Usage: scripts/fetch-brand-icons.sh [--help]

Downloads Simple Icons ${SI_VERSION} (CC0 1.0) from the GitHub tag tarball, verifies
its SHA-256, and writes:
  crates/vault-app/assets/brand-icons.tsv          slug<TAB>title<TAB>hex<TAB>path
  crates/vault-app/assets/brand-icons-LICENSE.md   upstream LICENSE with a preamble

The TSV is sorted by slug, LF-terminated, has no header, and is deterministic.
Entries that cannot be matched or contain tabs/newlines are skipped with a warning;
the script fails if more than 1% are skipped.

To bump the version, edit SI_VERSION and SI_SHA256 at the top of this script.
Requires: bash, curl, tar, shasum or sha256sum, python3 (run with -I), mktemp.
Needs network access; the app itself never does.
USAGE
}

case "${1:-}" in
  -h | --help) usage; exit 0 ;;
  "") ;;
  *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS="$ROOT/crates/vault-app/assets"
mkdir -p "$ASSETS"

if command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  sha256() { sha256sum "$1" | awk '{print $1}'; }
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Downloading Simple Icons ${SI_VERSION}..." >&2
curl --proto '=https' --tlsv1.2 -sSfL -o "$WORK/si.tar.gz" "$SI_URL"

actual="$(sha256 "$WORK/si.tar.gz")"
if [ "$actual" != "$SI_SHA256" ]; then
  echo "SHA-256 mismatch for ${SI_URL}" >&2
  echo "  expected: ${SI_SHA256}" >&2
  echo "  actual:   ${actual}" >&2
  exit 1
fi

mkdir "$WORK/src"
tar -xzf "$WORK/si.tar.gz" -C "$WORK/src" --strip-components=1

for f in data/simple-icons.json icons LICENSE.md; do
  [ -e "$WORK/src/$f" ] || { echo "missing $f in tarball" >&2; exit 1; }
done

# Slug rule mirrors upstream sdk.mjs: explicit "slug" field, else titleToSlug(title).
python3 -I - "$WORK/src" "$WORK/out.tsv" <<'PY'
import json, os, re, sys, unicodedata

src, out = sys.argv[1], sys.argv[2]
REPL = {'+': 'plus', '.': 'dot', '&': 'and', 'đ': 'd', 'ħ': 'h', 'ı': 'i', 'ĸ': 'k',
        'ŀ': 'l', 'ł': 'l', 'ß': 'ss', 'ŧ': 't', 'ø': 'o'}

def slug_of(entry):
    if entry.get('slug'):
        return entry['slug']
    t = entry['title'].lower()
    t = ''.join(REPL.get(c, c) for c in t)
    t = unicodedata.normalize('NFD', t)
    return re.sub(r'[^a-z0-9]', '', t)

SVG_RE = re.compile(r'^<svg[^>]*>\s*<title>[^<]*</title>\s*<path d="([^"]*)"\s*/>\s*</svg>\s*$')
HEX_RE = re.compile(r'^[0-9A-Fa-f]{6}$')
PATH_RE = re.compile(r'^[mMzZlLhHvVcCsSqQtTaAeE0-9,. \-]+$')

with open(os.path.join(src, 'data', 'simple-icons.json'), encoding='utf-8') as fh:
    meta = json.load(fh)

files = {f[:-4] for f in os.listdir(os.path.join(src, 'icons')) if f.endswith('.svg')}
total = len(files)
skipped = 0
rows = {}
seen_meta = set()

def skip(msg):
    global skipped
    skipped += 1
    print('warning: skipped ' + msg, file=sys.stderr)

for e in meta:
    try:
        slug = slug_of(e)
        title, hexc = e['title'], e['hex']
    except (KeyError, TypeError):
        skip('metadata entry without title/hex: %r' % (e,))
        continue
    if slug in seen_meta:
        skip('duplicate slug %s' % slug)
        continue
    seen_meta.add(slug)
    if slug not in files:
        skip('%s: no icon file' % slug)
        continue
    with open(os.path.join(src, 'icons', slug + '.svg'), encoding='utf-8') as fh:
        m = SVG_RE.match(fh.read())
    if not m:
        skip('%s: not a single-path SVG' % slug)
        continue
    path = m.group(1)
    if not HEX_RE.match(hexc):
        skip('%s: bad hex %r' % (slug, hexc))
        continue
    if not PATH_RE.match(path):
        skip('%s: unexpected path characters' % slug)
        continue
    if not re.match(r'^[a-z0-9_]+$', slug):
        skip('%s: bad slug' % slug)
        continue
    if any(c in f for f in (slug, title, hexc, path) for c in '\t\n\r'):
        skip('%s: field contains tab or newline' % slug)
        continue
    rows[slug] = (slug, title, hexc.upper(), path)

for slug in sorted(files - seen_meta):
    skip('%s: icon file without metadata' % slug)

limit = max(1, total // 100)
with open(out, 'w', encoding='utf-8', newline='\n') as fh:
    for slug in sorted(rows):
        fh.write('\t'.join(rows[slug]) + '\n')
print('icons: %d, skipped: %d' % (len(rows), skipped), file=sys.stderr)
if skipped * 100 > total:
    print('error: more than 1%% skipped (%d of %d)' % (skipped, total), file=sys.stderr)
    sys.exit(1)
PY

mv "$WORK/out.tsv" "$ASSETS/brand-icons.tsv"

{
  echo "Simple Icons ${SI_VERSION} (https://github.com/simple-icons/simple-icons), CC0 1.0."
  echo "Generated $(date -u +%Y-%m-%d) by scripts/fetch-brand-icons.sh. Brands remain trademarks of their owners."
  cat "$WORK/src/LICENSE.md"
} > "$ASSETS/brand-icons-LICENSE.md"

count="$(wc -l < "$ASSETS/brand-icons.tsv" | tr -d ' ')"
size="$(wc -c < "$ASSETS/brand-icons.tsv" | tr -d ' ')"
echo "Wrote ${count} icons, ${size} bytes: ${ASSETS}/brand-icons.tsv"
