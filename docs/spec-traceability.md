# Spec-to-test traceability

Maps every guarantee in `specs/02-core-api.md` and `specs/03-sync.md` to named tests (testing-roadmap item 6 in `specs/00-overview.md`).

Test notation, all names grep-verified:
- `core::<file>::<test>` is `crates/vault-core/tests/<file>.rs`. `core::src/<mod>::<test>` is a unit test in `crates/vault-core/src/`.
- `sync::<file>::<test>` is `crates/vault-sync/tests/<file>.rs`. `sync::src/<mod>::<test>` is a unit test in `crates/vault-sync/src/`.
- `qa::<file>::<test>` is `qa/spec-checks/tests/<file>.rs`. `qa::cli` is `qa/spec-checks/cli/run_all.sh`.
- `lab::<scenario>` is a scenario in `scripts/sync-lab/scenarios.sh`.

Coverage: `direct` asserts exactly this rule. `indirect` is exercised by a broader test. `none` has no test.

## 02 Core API

### Behavioural guarantees

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 02§G-1 | parse(serialize(v)).unlock == v | core::roundtrip::guarantee_1_roundtrip_100_items; qa::format::f10_round_trip_100_and_fresh_nonces | direct |
| 02§G-2 | Two serialize calls differ in bytes, equal in items | core::roundtrip::guarantee_2_serialize_twice_differs_but_unlocks_equal; qa::format::f10_round_trip_100_and_fresh_nonces | direct |
| 02§G-3a | Wrong password gives WrongPassword | core::roundtrip::guarantee_3_wrong_password; qa::format::f09_wrong_password | direct |
| 02§G-3b | Wrong-password timing does not depend on which byte is wrong | qa::keys::k09_wrong_password_timing_coarse | indirect |
| 02§G-4 | Flipping any ct byte gives Tampered(Item(id)) | core::tamper::guarantee_4_flip_byte_in_item_ct; qa::format::f04_item_ct_flip_every_byte | direct |
| 02§G-5 | Removing an item record gives Tampered(Manifest) | core::tamper::guarantee_5_remove_item_record; qa::format::f06_drop_rollback_duplicate_reorder | direct |
| 02§G-6 | Replacing a record with an older serialize gives Tampered(Manifest) | core::tamper::guarantee_6_rollback_item_record; qa::format::f06_drop_rollback_duplicate_reorder | direct |
| 02§G-7 | Record moved into another vault gives Tampered(Item(id)) | core::tamper::guarantee_7_item_moved_between_vaults; qa::format::f07_swap_item_into_other_vault | direct |
| 02§G-8 | change_password keeps vault_key, enclave slot still unlocks | core::slots::guarantee_8_change_password_leaves_vault_key_unchanged; qa::keys::k01_change_password_keeps_vault_key | direct |
| 02§G-9 | delete then merge an older copy keeps the item deleted | core::merge::guarantee_9_delete_then_merge_older_copy_stays_deleted; qa::merge::m02_tombstone_rules | direct |
| 02§G-10 | password(symbols, length 4) has one of each enabled class | core::generator::guarantee_10_one_of_each_class_at_length_4; qa::totp_gen::g01_password_classes | direct |

### Other normative statements

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 02§kdf-1 | recommended is 64 MiB / 3 / 4, for_tests is 8 MiB / 1 / 1 | core::kdf::recommended_and_for_tests | direct |
| 02§kdf-2 | calibrate(target) tunes cost to the target duration (01 §6) | core::kdf::calibrate_tiny_target_returns_recommended | indirect |
| 02§kdf-3 | KDF params outside bounds are rejected at parse, t_cost capped at 16 | core::kdf::validate_bounds; core::kdf::t_cost_is_capped_at_16_in_validate_and_in_the_parser; qa::format::f16_hostile_kdf_params | direct |
| 02§fwd-1 | Unknown field kinds survive roundtrip, merge, search and export | core::forward_compat::unknown_field_kinds_roundtrip_merge_search_and_export; qa::format::f17_forward_preserved_through_edit_and_merge | direct |
| 02§fwd-2 | Unknown slot kinds are skipped on unlock and preserved in position | core::forward_compat::opaque_slot_is_skipped_on_unlock_and_preserved_in_position; qa::format::f15_slot_kinds | direct |
| 02§fwd-3 | Unknown keys survive a read/write cycle | core::roundtrip::unknown_keys_survive_roundtrip; core::fixtures::v1_forward_unknowns_survive_serialize_parse_roundtrip | direct |
| 02§zero-1 | Debug of Item and Field redacts secrets | core::src/item::debug_redacts_secrets; core::attachment::debug_redacts_key | direct |
| 02§zero-2 | Secrets are zeroized on drop, never plain String | none | none |
| 02§api-1 | unlock tries every password slot | qa::keys::k02_remove_slot_rules | indirect |
| 02§api-2 | Password is NFC-normalised before Argon2 | core::roundtrip::password_nfc_normalised_at_unlock; core::src/crypto::password_is_nfc_normalised_before_argon2; qa::format::f11_nfc_password | direct |
| 02§api-3 | unlock_with_kek errors on bad slot or kek | core::slots::unlock_with_kek_errors | direct |
| 02§api-4 | unlock_with_key first tag failure reports WrongPassword | core::sync_feature::tampered_first_item_is_conflated_with_wrong_key | direct |
| 02§api-5 | items() excludes tombstones, items_including_deleted does not | core::roundtrip::items_excludes_tombstones | direct |
| 02§api-6 | Every mutation stamps modified_at and device_id | core::roundtrip::insert_stamps_modified_at_and_device_id; core::mutation::update_bumps_changed_field_without_timestamp_and_item | direct |
| 02§api-7 | set_field on a password field pushes history, cap 10 | core::mutation::set_field_password_pushes_history_newest_first_capped | direct |
| 02§api-8 | update recomputes modified_at and diffs fields by id (rename is an edit) | core::field_id::update_creates_tombstones_bumps_changed_fields_and_treats_rename_as_edit; qa::field_ids::fi06_update_diff_by_id | direct |
| 02§api-9 | update rejects duplicate field ids and restores the item | core::field_id::ids_round_trip_with_duplicate_and_empty_names | indirect |
| 02§api-10 | set_field_named is ASCII case-insensitive, NotFound / Ambiguous errors | core::field_id::set_field_named_ambiguity_not_found_and_case | direct |
| 02§api-11 | Item::field skips sections and empty names | core::src/item::field_lookup_by_name_skips_sections_and_empty_names | direct |
| 02§api-12 | remove_field writes a removed_fields marker | core::field_id::remove_field_restamps_and_lifts_to_the_field_stamp; qa::field_ids::fi07_remove_field_markers_cap_and_order | direct |
| 02§api-13 | upgrade_format v1 to v2, drops non-password slots, idempotent | core::field_id::upgrade_format_rewraps_password_slots_drops_the_rest_and_is_idempotent; qa::upgrade::u01_upgrade_drops_non_password_slots | direct |
| 02§api-14 | delete keeps a tombstone, purge_tombstones_older_than removes it | core::mutation::delete_tombstones_and_purge; qa::merge::m13_purge | direct |
| 02§api-15 | remove_slot refuses the last password slot | core::slots::remove_slot_refuses_last_password_slot_and_removes_enclave; qa::keys::k02_remove_slot_rules | direct |
| 02§api-16 | rotate_vault_key re-encrypts items, drops enclave slots | core::slots::rotate_vault_key_reencrypts_items_drops_enclave_and_keeps_old_file_valid; qa::keys::k04_rotate_vault_key | direct |
| 02§api-17 | merge_from errors on a different vault_id | core::merge::vault_id_mismatch_is_an_error; qa::merge::m09_foreign_vault_merge_refused | direct |
| 02§api-18 | serialize never fails | none | none |
| 02§api-19 | Attachment refs: add/remove validate and bump modified_at | core::attachment::ref_survives_serialize_parse_and_add_remove_bump_modified_at; core::attachment::invalid_refs_are_refused_on_every_write_path | direct |
| 02§totp-1 | TOTP RFC 6238 vectors for SHA1/256/512 | core::totp::rfc6238_vectors; qa::totp_gen::t02_against_independent_hmac | direct |
| 02§totp-2 | hotp URIs rejected | core::totp::hotp_rejected | direct |
| 02§totp-3 | URI normalisation: case, padding, spaces, dashes, no minimum length | core::totp::secret_normalisation; core::totp::short_and_odd_length_secrets; qa::totp_gen::t03_parse_normalisation | direct |
| 02§totp-4 | Scheme and host case-insensitive | core::totp::uppercase_scheme_and_host | direct |
| 02§totp-5 | Hostile URIs never panic | qa::totp_gen::t04_hostile_uris_no_panic | direct |
| 02§gen-1 | Defaults: password 20 chars all classes, passphrase 4 words | core::generator::default_passphrase_shape; core::generator::exclude_ambiguous_holds | indirect |
| 02§gen-2 | strength_bits penalises repeated runs and whole-string repeats | core::generator::strength_penalises_repetition; qa::totp_gen::g04_strength_bits | direct |
| 02§search-1 | Ranking order: title prefix, substring, host, username, tag, notes | core::search::ranking_order; qa::totp_gen::q01_search_ranking | direct |
| 02§search-2 | Case- and Unicode-insensitive, username field name ASCII case-insensitive | core::search::unicode_and_case_insensitive; core::src/search::username_field_name_is_case_insensitive | direct |
| 02§imp-1 | Imported items get fresh ids, caller now, importer device | core::csv::imported_rows_are_created_now_and_section_headings_are_not_exported; qa::import::i01_csv_round_trip | indirect |
| 02§imp-2 | created_at from source, unusable values fall back to now | core::onepux::created_at_ignores_unusable_values; core::kdbx::created_at_comes_from_the_entry_creation_time_or_now | direct |
| 02§imp-3 | KDBX limits: 100 MiB database, 1 MiB key file | core::kdbx::enforces_the_key_file_size_limit; qa::import::i04_kdbx_basic_and_limits | direct |
| 02§imp-4 | Import errors never leak values or parser text | core::onepux::malformed_error_does_not_leak_values; core::kdbx::imports_kdbx3_fixture_and_rejects_bad_inputs_without_leaking_values | direct |
| 02§imp-5 | Recycle bin skipped, history capped at 10, name collisions suffixed | core::kdbx::maps_fields_groups_history_and_skips_recycle_bin | indirect |
| 02§imp-6 | CSV export neutralises formula cells, field names case-insensitive | core::csv::formula_cells_are_neutralised_on_export_and_restored_on_import; core::csv::export_matches_field_names_case_insensitively | direct |

## 03 Sync

### §1 and §1.1 Layout and attachments

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§1-1 | Package layout: vault.bin, attachments/, backups/, tmp name | sync::src/package::layout; qa::sync::s01_save_layout | direct |
| 03§1-2 | Symlinked or non-directory attachments/backups dirs are refused | sync::untrusted_disk::symlinked_attachments_dir_is_refused_not_followed; sync::untrusted_disk::backups_dir_that_is_a_file_is_refused | direct |
| 03§1.1-1 | Blob writes are atomic, mode 0600 | sync::attachments::failed_seal_leaves_no_tmp_blob_or_ref; sync::src/atomic::replaces_existing_file | indirect |
| 03§1.1-2 | Reads call ensure_downloaded first, evicted gives NotDownloaded | sync::attachments::evicted_blob_is_not_downloaded; qa::sync_cloud::v02_cloud_hooks | direct |
| 03§1.1-3 | Absent blob is Missing, never blocks the item | sync::attachments::missing_blob | direct |
| 03§1.1-4 | Orphan blob deleted after a save that wrote, 24 h grace | sync::attachments::orphan_cleanup_after_save; sync::attachments::removed_attachment_blob_goes_after_the_grace_period; qa::attachments::a04_orphan_cleanup | direct |
| 03§1.1-5 | Cleanup once after unlock, only if primary read, clean, not blocked | sync::attachments::orphan_cleanup_runs_once_at_unlock | direct |
| 03§1.1-6 | Age is max(mtime, ctime) | sync::attachments::freshly_arrived_peer_blob_with_old_mtime_is_kept; sync::src/attachments::prune_counts_age_from_ctime_too | direct |
| 03§1.1-7 | Stale tmp files removed after 1 h | sync::src/attachments::stale_vault_tmp_is_removed_after_an_hour_only; sync::attachments::orphan_cleanup_after_save | direct |
| 03§1.1-8 | Cleanup never runs while locked | sync::attachments::prune_skips_clean_saves_and_locked_vaults; sync::robustness::stale_vault_tmp_is_removed_only_while_unlocked | direct |
| 03§1.1-9 | Tombstone keeps refs so the blob outlives deletion | sync::attachments::deleted_item_keeps_its_blob_while_tombstoned | direct |
| 03§1.1-10 | Peer reference judged after pre-save merge | sync::attachments::peer_prunes_unreferenced_blob_only_after_grace; sync::attachments::removal_survives_merge_on_both_devices_and_blob_is_pruned | indirect |
| 03§1.1-11 | Attachments are not in backups | none | none |
| 03§1.1-12 | 100 MB per-file cap | sync::attachments::size_cap_is_refused_before_reading; core::attachment::size_cap | direct |
| 03§1.1-13 | Provider label classifier (iCloud, CloudStorage prefix, Dropbox, local) | sync::src/cloud::cloud_storage_providers_by_folder_prefix; sync::src/cloud::icloud_drive_by_path_or_ubiquity; sync::src/cloud::legacy_dropbox_in_home; sync::src/cloud::ubiquity_is_not_queried_when_the_path_decides | direct |

### §2 Atomic save

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§2-1 | Tmp named .vault.bin.tmp-8hex in the package, created exclusively, mode 0600 | sync::src/atomic::tmp_name_matches_layout; sync::synced_vault::create_writes_parseable_private_file | direct |
| 03§2-2 | fsync(tmp) before rename | none | none |
| 03§2-3 | Rename is atomic, failure removes tmp and keeps the old file | sync::src/atomic::rename_failure_removes_tmp_and_keeps_target; sync::synced_vault::failed_save_leaves_original_intact | direct |
| 03§2-4 | Dir fsync ignores ENOTSUP/EINVAL/ENOSYS | sync::src/atomic::dir_sync_classifier | direct |
| 03§2-5 | Other dir fsync errors surface and the vault stays dirty | sync::src/atomic::dir_sync_error_is_reported_after_the_rename; sync::untrusted_disk::save_after_a_dir_fsync_failure_stays_dirty_and_retries | direct |
| 03§2-6 | last_written holds stat plus blake3, catches same-size same-tick rewrite | sync::robustness::same_size_same_mtime_rewrite_is_still_read; qa::sync_cloud::v01_same_size_forged_mtime_detected; sync::src/synced::fingerprint_after_write_drops_the_stat_of_a_replacement | direct |
| 03§2-7 | Save is followed by maybe_backup | sync::backups::first_save_after_unlock_snapshots | indirect |
| 03§2-8 | Exclusive flock on .lock around read-merge-write, no lost items | sync::robustness::concurrent_saves_from_two_threads_lose_nothing; sync::robustness::concurrent_saves_from_two_processes_lose_nothing; qa::sync::s12_concurrent_writers_no_lost_items | direct |
| 03§2-9 | Lock helper: exclusive excludes and times out, file is private | sync::src/lock::exclusive_excludes_and_times_out; sync::src/lock::shared_locks_coexist_and_file_is_private | direct |
| 03§2-10 | No locking on ENOTSUP/ENOLCK or permission failure: proceed unlocked | sync::src/lock::volume_without_locking_gets_a_no_op_guard; sync::src/lock::read_only_dir_without_lock_file_proceeds_unlocked | direct |
| 03§2-11 | Fallback warning logged once | none | none |
| 03§2-12 | Native no-replace rename for backups and blobs, hard-link fallback | sync::src/atomic::no_replace_refuses_existing_target; sync::src/atomic::no_replace_falls_back_to_hard_link_without_exclusive_rename; sync::src/atomic::rename_no_replace_moves_files_and_directories_and_never_clobbers | direct |
| 03§2-13 | Reads of vault.bin capped at 64 MiB with a typed error | sync::untrusted_disk::oversized_primary_is_refused_by_open; sync::untrusted_disk::oversized_backup_is_refused_by_restore | direct |
| 03§2-14 | Never write in place or truncate | sync::synced_vault::failed_save_leaves_original_intact | indirect |

### §3 Watching and reacting

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§3-1 | One recursive watch on the package parent, no initial scan | sync::watch::symlinked_package_is_resolved_and_watched | indirect |
| 03§3-2 | Debounce is 500 ms | sync::watch::watcher_ignores_attachments_backups_and_non_package_siblings | indirect |
| 03§3-3 | Package dir or vault.bin event means primary changed | sync::src/watch::event_places; sync::watch::two_devices_converge_on_field_edits | direct |
| 03§3-4 | attachments/**, backups/** and tmp files are ignored | sync::src/watch::event_places; sync::watch::watcher_ignores_attachments_backups_and_non_package_siblings | direct |
| 03§3-5 | Sibling packages and vault*.bin variants are conflict candidates, deeper paths ignored | sync::src/watch::conflict_patterns; sync::src/watch::inner_conflict_patterns; sync::src/watch::event_places | direct |
| 03§3-6 | Late blob in a sibling package re-triggers the deferred move | sync::attachments::conflict_package_waits_for_a_late_blob; sync::watch::conflict_package_whose_vault_file_arrives_late_is_absorbed | indirect |
| 03§3-7 | Names compared NFC-insensitively on both sides | sync::src/watch::nfd_event_paths_classify_like_nfc; sync::src/watch::nfd_siblings_match_the_nfc_package_name; sync::watch::package_named_in_another_normalisation_form_is_still_primary; sync::src/package::names_compare_after_nfc | direct |
| 03§3-8 | Nothing renamed on disk, fs ops use the supplied spelling | sync::watch::sibling_in_another_normalisation_form_is_absorbed | indirect |
| 03§3-9 | Step 1: stat equals last_written means ignore | sync::watch::own_save_is_not_merged; qa::sync::s16_echo_suppressed | direct |
| 03§3-10 | Step 2: equal blake3 means ignore | sync::watch::own_save_is_not_merged | indirect |
| 03§3-11 | Step 3: parse failure emits CorruptOnDisk, no overwrite, memory kept | sync::watch::corrupt_primary_is_reported_and_rewritten_on_save; qa::sync::s08_corrupt_primary | direct |
| 03§3-12 | Step 4: different vault_id emits ForeignVault and is ignored | sync::watch::foreign_primary_then_clean_lock_preserves_our_state | direct |
| 03§3-13 | Step 5: locked emits ChangedWhileLocked, unlock reads disk | sync::watch::change_while_locked_is_seen_at_unlock; qa::sync::s13_changed_while_locked | direct |
| 03§3-14 | Step 6a: unlock the disk copy with the cached key | core::sync_feature::unlock_with_key_matches_password_unlock_and_sets_device_id | direct |
| 03§3-15 | Step 6b/6c: merge, save if ours changed | sync::watch::two_devices_converge_on_field_edits; qa::sync::s03_two_handles_converge_via_watcher | indirect |
| 03§3-16 | Step 6d: emit Merged(report) | sync::hardening::save_without_watcher_merges_a_peer_write_first | direct |
| 03§3-17 | Step 6e: write back when ours has what disk lacks | sync::watch::delete_after_edit_wins; lab::different_fields | indirect |
| 03§3-18 | Pre-save merge of the current primary | sync::hardening::save_without_watcher_merges_a_peer_write_first; qa::sync::s12_concurrent_writers_no_lost_items | direct |
| 03§3-19 | Newer format or foreign vault on disk blocks save, SaveBlocked, memory kept | sync::hardening::newer_format_on_disk_blocks_save_until_a_valid_file_returns; sync::hardening::foreign_vault_on_disk_blocks_save_and_lock_preserves_edits; qa::sync::s09_save_blocked | direct |
| 03§3-20 | Ping-pong converges, merge idempotent and commutative | core::merge_props::merge_is_commutative; core::merge_props::merge_is_idempotent; lab::divergent_concurrent_adds | direct |
| 03§3-21 | Dirty edits stay when an external change merges in, no discard dialog | qa::sync_edge::e01_dirty_merge_keeps_both | direct |

### §4 Backups

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§4-1 | Snapshot if no snapshot newer than 1 h | sync::src/backup::snapshot_policy; sync::backups::fresh_conflict_file_does_not_suppress_hourly_snapshot | direct |
| 03§4-2 | Snapshot when item count decreased | sync::backups::deleting_an_item_takes_an_extra_snapshot; sync::hardening::failed_snapshot_for_a_deletion_is_retried | direct |
| 03§4-3 | Snapshot on first save after unlock | sync::backups::first_save_after_unlock_snapshots | direct |
| 03§4-4 | Two saves in a second take one snapshot | sync::backups::two_saves_in_a_second_take_one_snapshot; qa::sync::s02_backup_policy | direct |
| 03§4-5 | Snapshot is the exact bytes just written | qa::sync::s02_backup_policy | indirect |
| 03§4-6 | Name is name-UTC-stamp.vault.bin with dashes | sync::src/backup::stamp_known_instants_round_trip; sync::src/backup::file_names_parse | direct |
| 03§4-7 | -2, -3 suffixes within the same second | sync::src/backup::same_second_tie_breaks_on_suffix | indirect |
| 03§4-8 | -unsaved name for Unsaved backups | sync::src/backup::file_names_parse; sync::robustness::lock_while_dirty_preserves_the_edit_in_an_unsaved_backup | direct |
| 03§4-9 | Retention keeps all from the last 24 h | sync::src/backup::retention_buckets_at_1x; qa::retention::r01_retention_buckets | direct |
| 03§4-10 | Retention keeps one per day for 30 days | sync::src/backup::retention_buckets_at_1x | direct |
| 03§4-11 | Retention keeps one per week for 12 weeks | sync::src/backup::retention_buckets_at_1x | direct |
| 03§4-12 | Retention keeps one per month, cap 36 | sync::src/backup::monthly_cap_scales_and_newest_survives; sync::src/backup::retention_buckets_at_2x_keep_more | direct |
| 03§4-13 | Retention runs after each snapshot and deletes the rest | sync::backups::retention_runs_after_a_snapshot | direct |
| 03§4-14 | Settings: enable/disable | sync::backups::disabled_backups_skip_save_snapshots | direct |
| 03§4-15 | Settings: multiplier clamped to 0.5x to 4x | sync::src/backup::multiplier_is_clamped; sync::backups::retention_multiplier_is_clamped | direct |
| 03§4-16 | Back up now | sync::backups::backup_now_ignores_disabled_setting_and_policy; sync::backups::backup_now_copies_primary_even_while_locked | direct |
| 03§4-17 | Restore snapshots current first, wrong password changes nothing | sync::backups::restore_replaces_primary_and_snapshots_old_state; sync::backups::restore_with_wrong_password_changes_nothing | direct |
| 03§4-18 | Unsaved and Conflict backups are never pruned | sync::src/backup::unsaved_and_conflict_files_are_never_rotated | direct |
| 03§4-19 | restore_from works with an unparseable primary | sync::backups::restore_works_from_locked_and_over_a_corrupt_primary; sync::hardening::restore_over_unparseable_primary_keeps_its_raw_bytes | direct |
| 03§4-20 | delete_backup: inside backups/ only, refuses primary, any kind | sync::backups::delete_backup_refuses_anything_that_is_not_a_backup; sync::backups::delete_backup_removes_unsaved_and_conflict_packages_while_locked | direct |

### §5 Merge: item table

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§5-item-1 | Absent ours, present theirs: take theirs incl. tombstones | core::merge::absent_items_and_tombstones_are_added; qa::merge::m01_absent_present | direct |
| 03§5-item-2 | Present ours, absent theirs: keep ours | qa::merge::m01_absent_present | direct |
| 03§5-item-3 | Tombstone wins iff deleted_at >= other.modified_at | qa::merge::m02_tombstone_rules; core::merge::skewed_delete_stays_deleted_in_both_directions | direct |
| 03§5-item-4 | Edit after delete resurrects the live item | core::merge::edit_after_delete_resurrects; core::merge_props::delete_wins_over_older_copy_and_later_edit_resurrects | direct |
| 03§5-item-5 | Both live: title, favorite, tags, icon merge by own stamp | core::attr_stamps::rename_on_a_and_favorite_on_b_both_survive_in_one_round_both_orders; core::attr_stamps::tags_on_a_and_icon_on_b_both_survive; lab::rename_vs_favorite | direct |
| 03§5-item-6 | Attribute tie: greater device_id, then greater CBOR bytes | core::attr_stamps::same_attribute_on_both_sides_later_wins_and_ties_are_symmetric; core::merge::metadata_from_newer_side_tie_breaks_on_device_id | direct |
| 03§5-item-7 | Tags merge as one ordered list, reorder is a change | core::attr_stamps::tags_on_a_and_icon_on_b_both_survive | indirect |
| 03§5-item-8 | created_at keeps the minimum and is not a change | core::item_meta::merge_keeps_the_minimum_created_at_and_never_counts_it_as_a_change; qa::merge_ids::mi06_created_at_minimum_not_a_change | direct |
| 03§5-item-9 | Unstamped attributes follow the greater modified_at, ties by device_id then payload | core::attr_stamps::legacy_items_merge_as_before_and_sensibly_against_stamped_ones; core::merge_hunt::same_stamp_same_device_metadata_and_tombstones_pick_the_same_side; qa::upgrade::u11_legacy_items_without_stamps_merge_as_a_block | direct |
| 03§5-item-10 | Both tombstones converge, ties by payload bytes | core::merge::both_tombstones_converge; core::merge_hunt::same_stamp_same_device_metadata_and_tombstones_pick_the_same_side | direct |
| 03§5-item-11 | Result modified_at is max(ours, theirs) | core::merge::round_trip_after_merge | indirect |
| 03§5-item-12 | Merged item takes device_id of the winning metadata side | core::merge::metadata_from_newer_side_tie_breaks_on_device_id | direct |
| 03§5-item-13 | Icon travels with its stamp | core::icon::merge_keeps_the_winners_icon_and_a_differing_icon_is_a_change; qa::merge_ids::mi07_icon_travels_with_metadata | direct |

### §5 Merge: field table and collections

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§5-field-1 | Absent ours, present theirs: take theirs unless our marker covers it | core::merge::field_present_on_one_side_only_is_taken; core::field_id::tombstone_drops_the_field_on_the_other_device | direct |
| 03§5-field-2 | Present ours, absent theirs: keep ours unless their marker covers it | core::field_id::tombstone_drops_the_field_on_the_other_device; qa::merge_ids::mi03_removed_fields_two_devices | direct |
| 03§5-field-3 | Both: greater modified_at wins whole, rename is an edit | core::field_id::merge_by_id_rename_on_a_and_value_edit_on_b_converge_to_one_field; qa::merge::m03_field_level_lww; qa::merge_ids::mi02_rename_vs_edit | direct |
| 03§5-field-4 | Field tie: greater device_id, then greater CBOR bytes, converge in one round | core::merge_hunt::same_stamp_field_edits_converge_in_one_round_both_ways; qa::merge_ids::mi10_field_tie_with_shared_item_device_id_converges; qa::sync_edge::e10_same_stamp_field_edit_converges_through_sync | direct |
| 03§5-field-5 | Same name added on two devices keeps both (merge keyed by id) | qa::merge_ids::mi01_same_name_added_on_two_devices_both_kept; core::field_id::ids_round_trip_with_duplicate_and_empty_names | direct |
| 03§5-field-6 | removed_fields unioned, greatest removed_at per id | qa::merge_ids::mi03_removed_fields_two_devices; qa::merge_ids::mi04_removed_fields_three_devices_relay | direct |
| 03§5-field-7 | Field edited after its marker survives, marker dropped | core::field_id::edit_after_delete_resurrects_the_field_and_drops_the_marker; lab::field_removal_cycle | direct |
| 03§5-field-8 | Local removal never drops markers (soft cap locally) | core::field_id::tombstone_cap_is_soft_locally_purge_and_normalisation; qa::field_ids::fi07_remove_field_markers_cap_and_order | direct |
| 03§5-field-9 | Merge caps markers at 64, oldest first, only for fields neither side holds | qa::merge_ids::mi05_removed_fields_union_cap; core::merge_hunt::seventy_removals_on_one_device_survive_the_merge_with_an_offline_peer; qa::merge::m12_tombstone_caps | direct |
| 03§5-field-10 | Accepted limit: stale third device can resurrect a dropped field | qa::merge_ids::mi11_removals_beyond_cap_resurrect; lab::three_devices_removal_offline | direct |
| 03§5-field-11 | Conflict losers from removed fields do not enter history | core::field_id::removed_field_conflict_losers_do_not_enter_history | direct |
| 03§5-hist-1 | history union on (value, replaced_at), sorted, cap 10 newest | core::merge::history_union_and_cap; qa::merge::m05_history_and_removed_history | direct |
| 03§5-hist-2 | removed_history unioned, cap 10, matching entries dropped | core::history::removed_history_is_capped_newest_first_and_purged; core::history::removed_entry_stays_removed_after_merge_both_ways | direct |
| 03§5-hist-3 | set_field never reuses a removed stamp, max(now, stamp+1) | core::history::set_field_never_reuses_a_removed_stamp | direct |
| 03§5-hist-4 | Password conflict loser lands in history on both sides | core::merge::password_conflict_loser_lands_in_history_on_both_sides | direct |
| 03§5-att-1 | Attachment refs union on id, sorted by added_at then id | core::attachment::merge_unions_refs_sorted_by_added_at_then_id; qa::merge::m06_attachment_refs_merge | direct |
| 03§5-att-2 | Ref dropped when tombstone removed_at >= added_at | core::attachment::removed_ref_stays_removed_after_merge_both_ways; core::attachment::removal_under_a_clock_behind_the_add_still_wins_the_merge | direct |
| 03§5-att-3 | removed_attachments cap 64 in merge only, only for refs neither side holds | core::attachment::attachment_marker_cap_fires_only_in_merge_and_only_for_refs_neither_side_holds | direct |
| 03§5-att-4 | Local removal never drops removed_attachments markers | core::attachment::attachment_tombstones_are_never_capped_locally_and_are_purged | direct |

### §5 Header merge and stamps

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§5-hdr-1 | Greater (format_version, slots_modified_at, slots_device_id) wins, equal keeps ours | core::header_merge::greater_stamp_wins_in_both_directions_and_tie_keeps_ours; core::header_merge::equal_stamps_are_broken_by_device_id_and_converge_both_ways; qa::keys::k07_header_merge_rotation_and_tie_break | direct |
| 03§5-hdr-2 | Format version ranks first, an upgrade is never undone | core::merge_hunt::version_adoption_is_idempotent_and_commutative_and_never_lowers; core::merge_hunt::v2_holder_merging_a_newer_v1_header_keeps_version_2_and_its_slots; lab::v1_upgrade_propagates | direct |
| 03§5-hdr-3 | Winning header brings slots, KDF params and vault key | core::header_merge::key_rotation_on_b_is_adopted_together_with_its_key; core::header_merge::opaque_slots_and_kdf_extras_travel_with_the_header | direct |
| 03§5-hdr-4 | Later local slot change wins back by LWW | core::header_merge::later_local_password_change_beats_remote_rotation | direct |
| 03§5-hdr-5 | Password change or slot change survives the peer's next save | core::header_merge::password_change_and_recalibration_on_b_survive_a_merge; qa::keys::k06_header_merge_password_change_survives; qa::sync::s14_password_change_on_other_handle_survives | direct |
| 03§5-hdr-6 | Key rotation detected as KeyRotatedOnDisk | sync::watch::key_rotation_elsewhere_reports_rotation_and_reverify_merges; qa::sync::s15_key_rotated_elsewhere | direct |
| 03§5-mono-1 | Every write stamps max(now, previous + 1) | core::merge_props::stamps_are_monotone; qa::merge::m07_monotone_stamps | direct |
| 03§5-mono-2 | Backwards clock cannot resurrect a deleted item | core::merge::skewed_delete_stays_deleted_in_both_directions; core::merge::skewed_set_field_and_update_survive_merge | direct |
| 03§5-mono-3 | Content change at equal modified_at bumps it by one | core::merge::merge_that_changes_content_advances_modified_at_and_defeats_rollback; qa::merge::m11_equal_stamp_content_change_visible | direct |
| 03§5-mono-4 | Header stamp monotone under skew | qa::sync_edge::e06_header_stamp_monotone_under_skew; core::header_merge::fresh_vault_is_stamped_at_creation_and_every_slot_mutation_stamps_monotonically | direct |
| 03§5-conv-1 | Convergence within two rounds | core::merge_props::devices_converge_in_n_rounds; core::merge_props::replay_three_devices_two_rounds; qa::merge::m10_random_scripts_converge | direct |
| 03§5-conv-2 | Three rounds when the removed_fields cap fires | core::merge_props::devices_converge_in_n_plus_one_rounds_when_the_marker_cap_fires | direct |
| 03§5-rep-1 | merge_from returns a MergeReport with counts | core::merge::merge_is_idempotent_and_identical_copies_are_unchanged | indirect |
| 03§5-rep-2 | MergeReport.header_updated is set when the header changes | core::header_merge::password_change_and_recalibration_on_b_survive_a_merge | indirect |

### §6 Conflicted copies

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§6-pat-1 | Whole-package patterns: name 2.vault, conflicted copy .vault | sync::src/watch::conflict_patterns; sync::watch::icloud_numbered_copy_is_absorbed | direct |
| 03§6-pat-2 | Per-file patterns: vault (conflicted copy).bin, vault 2.bin | sync::src/watch::inner_conflict_patterns; sync::watch::dropbox_per_file_conflicted_copy_is_absorbed; sync::watch::numbered_per_file_copy_is_absorbed | direct |
| 03§6-pat-3 | Generic candidate with our vault_id is absorbed | sync::watch::generic_name_sibling_of_our_vault_is_absorbed | direct |
| 03§6-pat-4 | Patterns are case- and normalisation-insensitive, in dir only | sync::src/watch::non_ascii_and_spaced_names; sync::watch::sibling_in_another_normalisation_form_is_absorbed; sync::watch::watcher_ignores_attachments_backups_and_non_package_siblings | indirect |
| 03§6-step-1 | Foreign vault_id is ignored and left untouched | sync::watch::foreign_vault_sibling_is_left_alone; qa::sync::s07_foreign_conflict_copy_untouched; qa::sync_edge::e04_forged_conflict_header_rejected | direct |
| 03§6-step-2 | Locked: defer to next unlock, keep pending paths | sync::watch::conflict_seen_while_locked_is_absorbed_on_unlock; sync::watch::per_file_copy_seen_while_locked_is_absorbed_on_unlock; qa::attachments::a06_conflict_while_locked_deferred | direct |
| 03§6-step-3 | Merge theirs into ours and save | sync::watch::dropbox_conflicted_copy_is_absorbed; qa::sync::s05_sibling_package_conflict_absorbed; qa::sync::s06_in_package_conflict_absorbed | direct |
| 03§6-step-4a | Whole package: copy missing blobs, never replace | sync::attachments::conflict_package_with_extra_blob_is_absorbed_whole; sync::attachments::conflict_package_does_not_replace_existing_blobs; qa::attachments::a05_conflict_package_brings_blobs | direct |
| 03§6-step-4b | Whole package moved to backups/conflict-ts-name/ | sync::watch::icloud_numbered_copy_is_absorbed; sync::backups::restore_from_an_absorbed_conflict_package | direct |
| 03§6-step-4c | Package move deferred while referenced blobs are missing | sync::attachments::conflict_package_waits_for_a_late_blob; qa::sync_edge::e02_whole_package_deferred_until_blob | direct |
| 03§6-step-4d | Per-file copy moved to backups/conflict-ts-name.vault.bin | sync::watch::dropbox_per_file_conflicted_copy_is_absorbed | direct |
| 03§6-step-4e | Blob-only package contributes only referenced right-sized blobs | sync::untrusted_disk::blob_only_conflict_package_contributes_only_referenced_right_sized_blobs; sync::attachments::blob_only_conflict_package_contributes_its_blobs | direct |
| 03§6-step-5 | ConflictAbsorbed(path) emitted | sync::watch::dropbox_conflicted_copy_is_absorbed; sync::watch::icloud_numbered_copy_is_absorbed | direct |
| 03§6-wait-1 | WaitingForBlobs once per waiting package, never while locked | sync::attachments::conflict_package_waits_for_a_late_blob; qa::attachments::a06_conflict_while_locked_deferred | direct |
| 03§6-wait-2 | May fire again after absorb, vanish, lock, stop or start watching | sync::attachments::same_named_copy_waits_again_after_disappearing_while_unwatched; sync::attachments::still_waiting_package_is_reported_again_after_lock_and_unlock | direct |
| 03§6-wait-3 | ConflictAbsorbed follows when the blobs arrive | sync::attachments::conflict_package_waits_for_a_late_blob | direct |
| 03§6-never | A conflict copy is never deleted, only moved to backups | qa::attachments::a07_unopenable_conflict_copy_never_deleted; lab::conflict_copy_sibling; lab::conflict_copy_inpackage | direct |
| 03§6-lab | Numbered copies in both shapes converge | lab::conflict_copy_numbered_sibling; lab::conflict_copy_numbered_inpackage | direct |

### §7 CloudHooks

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§7-1 | Default hooks: is_evicted false, ensure_downloaded Ok, pin no-op | sync::backups::two_saves_in_a_second_take_one_snapshot | indirect |
| 03§7-2 | ensure_downloaded before every read of the primary | qa::sync_cloud::v02_cloud_hooks; sync::robustness::save_downloads_the_primary_before_taking_the_lock; sync::backups::backup_and_restore_wait_for_cloud_download | direct |
| 03§7-3 | ensure_downloaded before reading a conflict copy | none | none |
| 03§7-4 | pin after the first successful open | qa::sync_cloud::v02_cloud_hooks | direct |
| 03§7-5 | Timeout emits CloudUnavailable and nothing is overwritten | sync::hardening::save_does_not_overwrite_a_primary_it_cannot_download; sync::synced_vault::download_timeout_fails_open | direct |
| 03§7-6 | Default timeout is 30 s | none | none |
| 03§7-7 | Retry on the next watcher event | none | none |

### §8 Public API and SyncEvent

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§8-ev-Merged | Merged(report) fires after a merge of an external change | sync::hardening::save_without_watcher_merges_a_peer_write_first; sync::watch::two_devices_converge_on_field_edits | direct |
| 03§8-ev-ChangedWhileLocked | ChangedWhileLocked fires on an external change while locked | sync::watch::change_while_locked_is_seen_at_unlock | direct |
| 03§8-ev-ConflictAbsorbed | ConflictAbsorbed fires after a conflict copy is merged and moved | sync::watch::dropbox_conflicted_copy_is_absorbed | direct |
| 03§8-ev-WaitingForBlobs | WaitingForBlobs fires when a package move is deferred for blobs | sync::attachments::conflict_package_waits_for_a_late_blob | direct |
| 03§8-ev-CorruptOnDisk | CorruptOnDisk fires when the primary fails to parse | sync::watch::corrupt_primary_is_reported_and_rewritten_on_save | direct |
| 03§8-ev-ForeignVault | ForeignVault fires for a different vault_id | sync::watch::foreign_vault_sibling_is_left_alone; sync::watch::foreign_sibling_is_reported_once_per_content | direct |
| 03§8-ev-CloudUnavailable | CloudUnavailable fires when ensure_downloaded times out | sync::hardening::save_does_not_overwrite_a_primary_it_cannot_download | direct |
| 03§8-ev-BackupTaken | BackupTaken fires for each snapshot | sync::watch::own_save_is_not_merged; sync::robustness::lock_while_dirty_preserves_the_edit_in_an_unsaved_backup | indirect |
| 03§8-ev-BackupDeleted | BackupDeleted fires on delete_backup | sync::backups::delete_backup_removes_a_snapshot | direct |
| 03§8-ev-AttachmentsPruned | AttachmentsPruned(n) fires when cleanup deletes blobs | sync::attachments::removal_survives_merge_on_both_devices_and_blob_is_pruned; sync::attachments::orphan_cleanup_after_save | direct |
| 03§8-ev-PrimaryMissing | PrimaryMissing fires once, vault kept dirty, next save recreates | sync::untrusted_disk::deleted_primary_seen_by_the_watcher_marks_dirty_once_and_save_recreates_it; sync::untrusted_disk::unlock_over_a_deleted_primary_marks_dirty | direct |
| 03§8-ev-KeyMismatch | KeyMismatch fires when the disk file no longer opens with the cached key | sync::watch::password_change_with_rotation_elsewhere_reports_key_mismatch; sync::hardening::key_mismatch_refuses_clean_save_kek_unlock_and_preserves_on_lock | direct |
| 03§8-ev-KeyRotatedOnDisk | KeyRotatedOnDisk fires after a rotation elsewhere | sync::watch::key_rotation_elsewhere_reports_rotation_and_reverify_merges; qa::sync::s15b_key_rotation_event_kind | direct |
| 03§8-ev-SaveBlocked | SaveBlocked fires at first detection and once per refused save | sync::hardening::newer_format_on_disk_blocks_save_until_a_valid_file_returns; qa::sync::s09b_save_blocked_is_an_event | direct |
| 03§8-ev-Error | Error(String) fires for failures that are not typed events | sync::backups::failed_first_snapshot_is_retried_on_next_save; sync::untrusted_disk::symlinked_backups_dir_is_refused_and_lock_reports_unpreserved | indirect |
| 03§8-lock | lock returns Clean, Snapshotted(path) or Unpreserved(error) | sync::untrusted_disk::lock_outcome_clean_and_snapshotted; sync::untrusted_disk::symlinked_backups_dir_is_refused_and_lock_reports_unpreserved; qa::sync::s10_lock_with_unsaved_edits | direct |
| 03§8-kinds | Retention prunes Snapshot only, restore snapshots current first | sync::src/backup::unsaved_and_conflict_files_are_never_rotated; sync::backups::conflict_files_are_listed_and_unknown_files_ignored | direct |
| 03§8-auto | Autosave 2 s after last edit is app-side, vault-sync has no timer | none | none |
| 03§8-api | edit errors when locked, open/create/unlock lifecycle | sync::synced_vault::locked_operations_fail; sync::synced_vault::lock_then_unlock_again; sync::synced_vault::create_refuses_existing_path | direct |

### §9 Listed tests

| Rule id | Rule | Test(s) | Coverage |
|---|---|---|---|
| 03§9-1 | Save gives parseable file, no tmp, last_written set | sync::synced_vault::create_writes_parseable_private_file; qa::sync::s01_save_layout | direct |
| 03§9-2 | Two devices edit different fields and converge | sync::watch::two_devices_converge_on_field_edits; lab::different_fields | direct |
| 03§9-3 | Delete vs later edit, and edit vs later delete | sync::watch::edit_after_delete_wins; sync::watch::delete_after_edit_wins; lab::delete_vs_edit | direct |
| 03§9-4 | Dropbox-pattern file absorbed and moved | sync::watch::dropbox_conflicted_copy_is_absorbed | direct |
| 03§9-5 | Foreign *.vault gives ForeignVault, untouched | sync::watch::foreign_vault_sibling_is_left_alone | direct |
| 03§9-6 | Corrupt primary: CorruptOnDisk, memory intact, next save rewrites | sync::watch::corrupt_primary_is_reported_and_rewritten_on_save | direct |
| 03§9-7 | Retention over 200 synthetic snapshots | sync::src/backup::retention_buckets_at_1x; qa::retention::r01_retention_buckets | direct |

## Summary

Rows are counted by the Coverage column. The 02 section covers guarantees plus other normative statements. The 03 section covers all of §1 to §9.

| Spec | Rows | direct | indirect | none |
|---|---|---|---|---|
| 02 | 53 | 44 | 7 | 2 |
| 03 | 167 | 139 | 21 | 7 |
| Total | 220 | 183 | 28 | 9 |

Direct versus indirect is judged from test names and doc comments, not from reading every assertion. Treat a `direct` row as a pointer to confirm, not as proof.

## Uncovered rules

| Rule id | Rule | Why it matters |
|---|---|---|
| 02§zero-2 | Secrets are zeroized on drop, never plain String | Name-only check is impossible. Needs a review gate or a type-level lint. |
| 02§api-18 | serialize never fails | Only enforced by the signature. Low risk. |
| 03§1.1-11 | Attachments are not in backups | Owner decision with no test pinning it. A change would go unnoticed. |
| 03§2-2 | fsync(tmp) before rename | Durability claim with no fault-injection test. |
| 03§2-11 | Lock fallback warning logged once | Behaviour is tested, the logging is not. |
| 03§7-3 | ensure_downloaded before reading a conflict copy | Only primary and blob reads are tested. An evicted conflict copy could be misread as corrupt. |
| 03§7-6 | Default download timeout is 30 s | Constant not asserted. |
| 03§7-7 | CloudUnavailable retries on the next watcher event | No test drives a second event after a timeout. |
| 03§8-auto | Autosave 2 s after last edit | App-side by design. Belongs in a `vault-app` test. |
