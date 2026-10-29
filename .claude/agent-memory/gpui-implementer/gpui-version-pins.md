---
name: gpui-version-pins
description: Which gpui / gpui-component crates and versions vault-app pins, why gpui-pre not gpui, toolchain and Metal requirements
metadata:
  type: project
---

Pinned 2026-10-29 (package P2.0), all from crates.io, all owned by `huacnlee` (Longbridge, gpui-component maintainer):
- `gpui = { package = "gpui-pre", version = "=0.3.10" }` (snapshot of zed@08cbb88). crates.io `gpui` is stuck at 0.2.2 (2025-10) and is NOT what gpui-component uses.
- `gpui_platform = { package = "gpui-pre-platform", "=0.3.10", features = ["font-kit"] }` provides `gpui_platform::application()`. `font-kit` is NOT default in gpui-pre-platform/-macos/-apple. Without it macOS uses a no-op text system: quads draw, zero glyphs, `all_font_names()` is empty, and the only sign is a `log::warn!` ("compiled without the `font-kit` feature") that nobody sees because vault installs no logger. Fixed 2026-10-29.
- macOS target dep `gpui_macos = { package = "gpui-pre-macos", "=0.3.10", features = ["runtime_shaders"] }`.
- `gpui-component`, `gpui-component-macros`, `gpui-base`, `gpui-kit-assets` all `=0.8.1`.
- Upstream now recommends the `gpui-kit` facade crate (`gpui_kit::application()`, `gpui_kit::open_window` mounts Root). We deliberately skipped it; using it would also be valid.

**Why:** gpui-pre needs Rust >= ~1.93 (`slice::as_array`); verified on 1.99.1, installed as `rustup toolchain 1.99.1` alongside default 1.89. vault-app sets `rust-version = "1.99"`. Precompiled Metal shaders need `xcodebuild -downloadComponent MetalToolchain` (missing here), hence `runtime_shaders`.
**How to apply:** `rust-toolchain.toml` pins 1.99.1 at the repo root (since 2026-10-29), so plain `cargo` works. Before bumping, re-check owners/deps on crates.io and that gpui-component's `[dependencies.gpui]` still names `gpui-pre`. See [[gpui-api-facts]] and [[gpui-component-theme]].
