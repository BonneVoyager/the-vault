#!/usr/bin/env bash
# Render only the vault wheel region over the stationary app icon.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - "$here/vault.svg" "$tmp" <<'PY'
from pathlib import Path
from math import cos, pi
import sys

source = Path(sys.argv[1]).read_text()
start = '    <!-- six-spoke vault wheel: top, bottom, and four diagonals -->'
end = '    <path d="M486 430'
assert source.count(start) == source.count(end) == 1
before, wheel_and_rest = source.split(start, 1)
wheel, after = wheel_and_rest.split(end, 1)
for frame in range(48):
    progress = frame / 48
    angle = 180 * (1 - cos(pi * progress))  # ease in/out over one full turn
    svg = (before + f'    <g transform="rotate({angle} 486 503)">\n'
           + start + wheel + '    </g>\n' + end + after)
    (Path(sys.argv[2]) / f'{frame:02}.svg').write_text(svg)
PY

for svg in "$tmp"/*.svg; do
  full="${svg%.svg}-full.png"
  rsvg-convert -w 256 -h 256 "$svg" -o "$full"
  # 2x the 70 pt overlay at (26, 28) in the 128 pt icon slot.
  magick "$full" -crop 140x140+52+56 +repage "${svg%.svg}.png"
done
# GPUI displays each WebP frame independently, so mux complete frames.
frames=()
for png in "$tmp"/[0-9][0-9].png; do
  cwebp -quiet -lossless "$png" -o "${png%.png}.webp"
  frames+=(-frame "${png%.png}.webp" '+40+0+0+0-b')
done
webpmux "${frames[@]}" -loop 0 -o "$here/vault-wheel.webp"
