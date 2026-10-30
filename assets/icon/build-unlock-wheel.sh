#!/usr/bin/env bash
# Render vault-256-spokeless.png: vault-256.png without the wheel's spokes. While an
# unlock runs, the unlock screen shows it under wheel.svg, which it rotates.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - "$here/vault.svg" "$tmp/spokeless.svg" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
start = '    <!-- six-spoke vault wheel: top, bottom, and four diagonals -->'
end = '    <circle cx="486" cy="503" r="140" fill="none" stroke="#0084ff"'
assert source.count(start) == source.count(end) == 1
before, rest = source.split(start, 1)
_spokes, after = rest.split(end, 1)
Path(sys.argv[2]).write_text(before + end + after)
PY
rsvg-convert -w 256 -h 256 "$tmp/spokeless.svg" -o "$here/vault-256-spokeless.png"
