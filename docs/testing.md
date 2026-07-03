# Testing And Validation

This repository does not currently define npm `test`, npm `lint`, a docs build,
or a Markdown lint configuration. Choose validation commands based on the files
changed.

## Command Matrix

| Scope | Command | Notes |
| --- | --- | --- |
| Frontend or Vite changes | `npm run build` | Runs `tsc && vite build`. |
| Download IPC contract changes | `npm run validate:download-ipc` | Dependency-free static check that payload IDs are assigned from the Rust payload identity, stored with current task payload bytes, passed by every frontend download callsite as `file.id`, resolved by Rust before download, and listed in phase evidence. |
| Phase evidence review | `npm run validate:phase-evidence` | Dependency-free static check that the phase model, phase manifest, maintained docs, build-script gate, JPEG/PNG source evidence, named Rust analyzer test functions, local-file boundary, payload-ID download validator, and informational WAV pre-transition evidence still line up. It does not replace `npm run build` or Rust tests for a phase transition. |
| Static recovery chain | `npm run validate:static` | Dependency-free validator chain that syntax-checks local validator scripts, then runs the phase evidence validator directly; the phase evidence validator includes the download IPC contract check. |
| Toolchain readiness preflight | `npm run validate:toolchain-readiness` | Dependency-free setup check that classifies missing local `tsc`/`vite` binaries and offline Cargo metadata blockers before a transition validation attempt. |
| Rust or Tauri backend changes | `cargo check --manifest-path src-tauri/Cargo.toml` | Fast Rust/Tauri compile check. |
| Analyzer behavior changes | `cargo test --manifest-path src-tauri/Cargo.toml` | Runs inline Rust unit tests, including analyzer tests. |
| Release packaging | `npm run tauri -- build` | Runs the frontend build through Tauri and creates bundle artifacts. |
| Generic documentation-only changes | `git diff --check` | Checks whitespace and patch formatting when no docs-specific validator exists. |
| Phase handoff or validator documentation changes | `npm run validate:static` | Runs the dependency-free static chain that protects the phase handoff docs, validator wiring, and current evidence names. |

`npm ci` is setup, not validation. It creates `node_modules/` from the checked-in
lockfile and should be run only when dependencies need to be installed locally.

## Existing Coverage

Rust analyzer unit tests live inline in `src-tauri/src/domain/analyzer.rs`. The
cross-analyzer registry and finalization functions live in
`src-tauri/src/domain/analyzer_pipeline.rs` and are exercised by those analyzer
tests plus command-level tests. Existing tests cover representative payload
extraction behavior, including:

- RGB LSB extraction from image streams.
- Non-image media ignored by image-only analyzers.
- PNG metadata packet extraction.
- PNG metadata signature candidate extraction.
- PNG metadata boundary handling that ignores chunks after the structural
  `IEND` marker and refuses metadata extraction before a valid structural
  `IEND` terminator is present.
- Compressed PNG `zTXt`/`iTXt` metadata payload extraction.
- PNG after-IEND packet and signature candidate extraction, including invalid
  packet fallback to signature evidence and invalid `IEND` CRC rejection.
- JPEG COM/APP segment extraction, structural after-EOI signature extraction,
  APP0/APP15 boundary segment coverage, corrupt packet magic decoy recovery,
  invalid signature decoy recovery, non-payload marker segment exclusion,
  structural EOI requirement before segment payload extraction, malformed
  segment and non-marker header byte safety, non-JPEG/truncated input safety,
  scan-data isolation, marker-shaped scan-data isolation, byte-stuffed SOS EOI
  isolation, SOS restart/fill marker isolation, malformed SOS marker recovery,
  malformed SOS false-EOI length recovery, post-SOS marker-segment skipping,
  and after-EOI evidence labeling, including multiple verified packets after
  EOI, same-name packet preservation across segment and after-EOI channels, and
  verified packet preference over after-EOI signature fallback candidates.
- Container side-channel boundaries, including metadata chunks after structural
  PNG `IEND`, invalid or missing PNG `IEND` terminators, JPEG marker-like bytes
  after structural EOI, and same-name distinct payload preservation.
- WAV PCM sample LSB packet and signature extraction, plus unsupported or
  truncated WAV safety.
- Two-bit-per-pixel channel and matrix strategies.
- Verified packet payload byte recovery.
- Signature-only candidate suppression when verified packets exist.
- Invalid MP3 candidate rejection.

There are initial command-level Rust tests for create, byte-input attach,
path-based attach, invalid attach/analyze inputs, stale-task attach rejection
before media loader validation or local path inspection, path-based reattach
result clearing, path-attached JPEG segment and after-EOI analysis/download, analyze,
list-extracted-files success and missing-task rejection, download command flow,
malformed download request rejection, and same-name payload download
disambiguation for PNG metadata and JPEG segment carriers.
There are no frontend tests, negative-path command-level Rust tests for every
Tauri command, or end-to-end desktop workflow tests yet.

Analyzer fixtures are synthetic inline byte vectors or generated images. Do not
commit real evidence files, recovered private payloads, or generated fixture
artifacts for analyzer coverage.

## Recommended Validation By Change Type

For generic documentation-only changes:

```bash
git diff --check
```

When `docs/instructions/phase-gates.json` changes, also parse it:

```bash
python3 -m json.tool docs/instructions/phase-gates.json
```

For a dependency-free static review of the current phase evidence and
documentation handoff, or after editing phase handoff docs, run:

```bash
npm run validate:static
```

The phase evidence validator guards the README, architecture, onboarding,
maintenance, troubleshooting, and phase-readiness docs against drift from the
current phase, analyzer registry, named Rust analyzer test functions, local-file
boundary, payload ID download contract, and setup-blocker guidance.

When setup may be incomplete, run the readiness preflight before the transition
command:

```bash
npm run validate:toolchain-readiness
```

This command does not replace `npm run build`, `cargo check`, or `cargo test`.
It exits nonzero when local build dependencies are not installed or Cargo cannot
resolve the locked graph offline, so the blocker can be recorded before
spending a full transition validation attempt.

Documentation-only validation does not satisfy the phase transition gate. Before
changing `current_phase` in `docs/instructions/phase-gates.json`, rerun the
manifest's transition validation command and the Rust analyzer checks that prove
the selected analyzer package. See
[Analyzer Phase Readiness](phase-readiness.md) for the current evidence map.
That document also contains a gate-by-gate runbook for checking the JPEG, PNG,
Rust test, and frontend build evidence before a phase-transition patch.

If `npm run build` reports `tsc: not found`, stop and install local Node
dependencies before treating the transition command as a source failure:

```bash
npm ci
npm run build
```

Do not update phase state from a documentation-only run or from a build attempt
that stopped before TypeScript compilation began.

For frontend UI or IPC wrapper changes:

```bash
npm run validate:phase-evidence
npm run validate:download-ipc
npm run build
```

For the current frontend-to-Rust local-file attach boundary:

```bash
cargo test --manifest-path src-tauri/Cargo.toml attach_media_file_from_path_command_test_reads_local_media_path
cargo test --manifest-path src-tauri/Cargo.toml attach_media_file_from_path_command_test_rejects_missing_task_before_path_inspection
```

For Rust command, loader, task, or analyzer changes:

```bash
cargo check --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
```

For a focused review of the current container-side-channel analyzer package:

```bash
cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer
cargo test --manifest-path src-tauri/Cargo.toml png_container_analyzer
cargo test --manifest-path src-tauri/Cargo.toml compressed_png
cargo test --manifest-path src-tauri/Cargo.toml default_pipeline_extracts_container_side_channel_packets_from_registered_analyzers
```

The `png_container_analyzer` filter covers after-IEND payload tests. The
`compressed_png` filter covers the compressed `zTXt`/`iTXt` metadata tests that
also support the current PNG phase gate. The default-pipeline filter proves the
registered analyzer set emits both PNG after-IEND and JPEG after-EOI packet
payloads through the current pipeline.

For the pre-transition audio evidence, after the current
`container-side-channels` gate is otherwise ready:

```bash
cargo test --manifest-path src-tauri/Cargo.toml wav_pcm_lsb
```

This filter covers the audio analyzer package and default pipeline WAV evidence
without changing phase state by itself.

For the payload identity and same-name download path:

```bash
npm run validate:download-ipc
cargo test --manifest-path src-tauri/Cargo.toml finalize_extracted_payloads
cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids
cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids_uses_recovered_bytes_for_same_name_payloads
cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids_is_stable_for_identical_payload_identity
cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids_separates_payload_source_and_analyzer_identity
cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids_separates_embedded_name_and_file_type
cargo test --manifest-path src-tauri/Cargo.toml replace_extracted_payloads_dedupes_exact_payloads_before_assigning_ids
cargo test --manifest-path src-tauri/Cargo.toml replace_extracted_payloads_prefers_verified_payloads_before_assigning_ids
cargo test --manifest-path src-tauri/Cargo.toml metadata_analyzer_preserves_distinct_packets_with_same_embedded_name
cargo test --manifest-path src-tauri/Cargo.toml download_extracted_file_command_test_writes_current_payload_bytes
cargo test --manifest-path src-tauri/Cargo.toml download_extracted_file_command_test_rejects_stale_payload_id_after_result_replacement
cargo test --manifest-path src-tauri/Cargo.toml download_extracted_file_command_test_uses_file_id_for_same_name_payloads
cargo test --manifest-path src-tauri/Cargo.toml download_extracted_file_command_test_uses_file_id_for_same_name_signature_scan_payloads
cargo test --manifest-path src-tauri/Cargo.toml download_extracted_file_command_test_rejects_blank_payload_id
cargo test --manifest-path src-tauri/Cargo.toml download_extracted_file_command_test_rejects_missing_payload_bytes
cargo test --manifest-path src-tauri/Cargo.toml analyze_and_download_command_test_disambiguates_same_name_packet_payloads
cargo test --manifest-path src-tauri/Cargo.toml analyze_and_download_command_test_disambiguates_same_name_jpeg_segment_payloads
cargo test --manifest-path src-tauri/Cargo.toml analyze_and_download_command_test_disambiguates_same_name_jpeg_segment_after_eoi_payloads
cargo test --manifest-path src-tauri/Cargo.toml analyze_and_download_command_test_rejects_payload_id_after_reattach
```

These tests verify that exact duplicate payload records collapse, task storage
keeps verified packet payloads ahead of signature-only fallback candidates,
distinct same-name recovered byte streams remain visible for verified packets
and signature scans, JPEG segment and after-EOI same-name payloads download by
their current payload IDs, IDs for payloads no longer present in the current
result are rejected after result replacement or media reattach/reanalysis,
blank payload IDs fail required-field validation, and downloads use payload IDs
instead of the displayed file name. The missing payload filter covers the
negative path where the requested payload ID is not in the current result.

For release packaging changes or before creating a distributable:

```bash
npm run tauri -- build
```

## Coverage Gaps

Add these before treating the app as a stable MVP:

- Broaden remaining command-level tests for cross-command state transitions
  outside the current attach/analyze/download path.
- Frontend tests for task creation, media attachment, analyze button state,
  result rendering, error banners, and download dialog behavior.
- Broader test fixtures for supported media classes and known payload examples.
- Additional hardening for large media files, including removing the legacy
  byte-input attach command once no compatibility caller needs it. The current
  path-based attach boundary is summarized in
  [Architecture Notes](architecture.md).
