#!/usr/bin/env bash
# Build a compact strip of the original icon with its shaded spokes rotated.
# Frame 0 must match vault-256.png exactly, so idle and motion share one image.
# Also builds the keyhole flare overlay shown when an unlock succeeds.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - "$here/vault.svg" "$tmp" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
out = Path(sys.argv[2])
anchor = '    <!-- six-spoke vault wheel: top, bottom, and four diagonals -->\n    <g filter="url(#barShadow)">'
assert source.count(anchor) == 1
for frame in range(24):
    angle = frame * 2.5  # Six identical spokes: one 60-degree sector is enough.
    rotated = source.replace(anchor, anchor.replace('<g filter=', f'<g transform="rotate({angle} 486 503)" filter='), 1)
    (out / f'frame-{frame:02}.svg').write_text(rotated)

# The keyhole on its own: glow, body and highlight, the three paths after the hub.
# Body and highlight stay exact; the glow becomes a flare: a wide saturated blue halo
# (it must contrast with the light steel hub) around a white core.
head, body = source.split('  <g>\n', 1)
keyhole = [l for l in body.splitlines() if l.startswith(('    <path d="M486 43', '    <path d="M485 442'))]
assert len(keyhole) == 3
glow = """    <filter id="glow" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="7" result="blur"/>
      <feComponentTransfer><feFuncA type="linear" slope=".8"/></feComponentTransfer>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>"""
flare = """    <filter id="glow" x="-100%" y="-100%" width="300%" height="300%">
      <feGaussianBlur stdDeviation="28" result="halo"/>
      <feGaussianBlur stdDeviation="8" result="soft"/>
      <feFlood flood-color="#ffffff"/>
      <feComposite in2="soft" operator="in" result="core"/>
      <feMerge>""" + '<feMergeNode in="halo"/>' * 6 + """<feMergeNode in="core"/><feMergeNode in="SourceGraphic"/></feMerge>"""
assert head.count(glow) == 1 and keyhole[0].count('fill="#0056e8" opacity=".8"') == 1
head = head.replace(glow, flare)
keyhole[0] = keyhole[0].replace('fill="#0056e8" opacity=".8"', 'fill="#1f7dff"')
(out / 'keyhole.svg').write_text(head + '  <g>\n' + '\n'.join(keyhole) + '\n  </g>\n</svg>\n')
PY
for svg in "$tmp"/frame-*.svg; do
  rsvg-convert -w 256 -h 256 "$svg" -o "${svg%.svg}.png"
done
if ! cmp -s "$tmp/frame-00.png" "$here/vault-256.png"; then
  echo "error: frame 0 differs from vault-256.png; rebuild the source icon first" >&2
  exit 1
fi
magick "$tmp"/frame-*.png +append "$here/vault-wheel-strip.png"
# Same 256 px scale as the icon, cropped to even pixels (whole points at 128 pt) with
# room for the flare. Keep in step with KEYHOLE_* in crates/vault-app/src/screens/unlock.rs.
rsvg-convert -w 256 -h 256 "$tmp/keyhole.svg" -o "$tmp/keyhole-full.png"
if [ "$(magick "$tmp/keyhole-full.png" -format %@ info:)" != "65x79+89+90" ]; then
  echo "error: the keyhole moved; update the crop box and KEYHOLE_* constants" >&2
  exit 1
fi
magick "$tmp/keyhole-full.png" -crop 68x82+88+88 +repage -strip "$here/vault-keyhole.png"
