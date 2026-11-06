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
- __TEXT,__const is ~6.6 MB, of which ~4.5 MB is `include_str!` of crates/vault-app/assets/brand-icons.tsv (icon.rs BRAND_TSV);
  compressing it is the next big size win (app-code change). App already embeds only a subset of gpui-kit-assets icons (icon_assets!).
- image codecs (exr, webp, tiff...) are hard-enabled by gpui-pre itself; cannot be dropped from vault-app. regex comes via gpui too.
- Perf benches here are noisy: other agents compile concurrently (load avg 15-60 on 10 cores) and edit crates mid-run
  (builds can break transiently). Use seeded single-thread proptests: `PROPTEST_RNG_SEED=42 VAULT_PROPTEST_CASES=200 <merge_props bin> --test-threads=1`
  (~15-16 s), and run the test binary directly, not via cargo. A dist build from scratch takes ~4 min (fat LTO).
- CLI `init` without --kdf-test-params calibrates (m=512 MiB, t=3, p=4 here), so create bench vaults once and reuse copies.
