#!/usr/bin/env bash
# Rasterize assets/icon/vault.svg into assets/icon/Vault.icns using macOS tools.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
svg="$here/vault.svg"
out="$here/Vault.icns"
tmp="$(mktemp -d)"
iconset="$tmp/vault.iconset"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$iconset"

if command -v rsvg-convert > /dev/null 2>&1; then
  method=rsvg
elif command -v qlmanage > /dev/null 2>&1; then
  method=qlmanage
else
  echo "error: no rasterizer found (need rsvg-convert or qlmanage)" >&2
  exit 1
fi
command -v iconutil > /dev/null 2>&1 || { echo "error: iconutil not found" >&2; exit 1; }
if [[ $method == qlmanage ]]; then
  command -v sips > /dev/null 2>&1 || { echo "error: sips not found (needed with qlmanage)" >&2; exit 1; }
fi
echo "==> Rasterizing with $method"

render() { # size outfile
  local size="$1" dest="$2"
  case "$method" in
    rsvg) rsvg-convert -w "$size" -h "$size" "$svg" -o "$dest" ;;
    qlmanage)
      local d="$tmp/ql$size"
      mkdir -p "$d"
      qlmanage -t -s "$size" -o "$d" "$svg" > /dev/null 2>&1
      [[ -f "$d/vault.svg.png" ]] || { echo "error: qlmanage produced no output for $size" >&2; exit 1; }
      sips -s format png "$d/vault.svg.png" --out "$dest" > /dev/null
      ;;
  esac
  [[ -s "$dest" ]] || { echo "error: failed to render $dest" >&2; exit 1; }
}

for base in 16 32 128 256 512; do
  render "$base" "$iconset/icon_${base}x${base}.png"
  render "$((base * 2))" "$iconset/icon_${base}x${base}@2x.png"
done

iconutil -c icns "$iconset" -o "$tmp/Vault.icns"
mv "$tmp/Vault.icns" "$out"
echo "==> Wrote $out ($(wc -c < "$out" | tr -d ' ') bytes)"
