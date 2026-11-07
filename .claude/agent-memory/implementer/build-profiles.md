---
name: build-profiles
description: [profile.dist] (fat LTO, cgu=1, strip, packed line-table dSYM), binary size contributors, bench protocol and noise sources for perf measurements
metadata:
  type: project
---

`[profile.dist]` in the workspace Cargo.toml is the shipping profile; scripts/package.sh builds with
`--profile dist` and copies target/dist/vault-app plus target/dist/vault-app.dSYM (a symlink into deps/, so `cp -RL`)
to target/package/Vault.app.dSYM. `[profile.release]` is intentionally untouched (fast iteration).

**Why:** 2026-11-06 measurement: release vault-app 39.5 MB (76k symbols; cargo strips only debuginfo, not the symtab),
lto=thin is *bigger* (40.2 MB), fat 30.1, fat+cgu1 28.9, +strip/line-tables 24.7 MB, no speed loss.
panic=abort (20.9 MB) is banned by the orchestrator: catch_unwind boundaries (KDBX parser, background tasks) need unwinding.
gpui's own catch_unwind uses are all in tests. opt-level="s" (20.8 MB) costs ~22% unlock and ~30% merge proptest time.

**How to apply:**
- brand-icons.tsv (4.69 MB) is now zlib-compressed by crates/vault-app/build.rs into OUT_DIR (2.00 MB) and inflated
  lazily in icon.rs (2026-11-07): dist 24,978,048 -> 22,303,200 B. First BrandPack::get() in release ~33 ms
  (inflate ~19 ms miniz_oxide + parse ~13 ms). Warmed by a detached background task in state.rs `run_bg_timed` when
  `busy.is_unlock()` (covers password + Touch ID); the single Box::leak lives in the PACK initialiser (coordinator review).
- `collapse_tests::mid_slide_inset_follows_the_sidebar_width` uses real-time sleeps and flakes in the full suite under load;
  passes alone. Not a regression signal. App already embeds only a subset of gpui-kit-assets icons (icon_assets!).
- In agent sessions bare `rustfmt` (and shell loops / `$(...)`) can be blocked by the permission layer; `cargo fmt -p X -- --check`
  works, so read its diff and hand-apply. The repo rustfmt config wraps shorter than 100 cols (don't guess, check).
- image codecs (exr, webp, tiff...) are hard-enabled by gpui-pre itself; cannot be dropped from vault-app. regex comes via gpui too.
- Perf benches here are noisy: other agents compile concurrently (load avg 15-60 on 10 cores) and edit crates mid-run
  (builds can break transiently). Use seeded single-thread proptests: `PROPTEST_RNG_SEED=42 VAULT_PROPTEST_CASES=200 <merge_props bin> --test-threads=1`
  (~15-16 s), and run the test binary directly, not via cargo. A dist build from scratch takes ~4 min (fat LTO).
- CLI `init` without --kdf-test-params calibrates (m=512 MiB, t=3, p=4 here), so create bench vaults once and reuse copies.
