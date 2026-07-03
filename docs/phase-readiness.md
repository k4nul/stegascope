# Analyzer Phase Readiness

This note records the documentation-facing evidence for the current
`container-side-channels` phase, the boundary before `audio-lsb-analysis`, and
the pre-transition audio analyzer evidence that already exists in source.
It is not a phase transition record; `current_phase` stays unchanged until the
transition validation command and required analyzer evidence gates pass locally.

## Current Phase

`docs/instructions/phase-gates.json` declares:

- current phase: `container-side-channels`
- next phase: `audio-lsb-analysis`
- transition validation command: `npm run build`

The current phase covers the first image-container analyzer package:

- JPEG COM/APP0-APP15 segment payload scanning.
- JPEG payload bytes appended after the structural EOI marker.
- PNG compressed `zTXt` and `iTXt` text payload scanning after a valid
  structural `IEND` terminator is present.
- PNG payload bytes appended after the structural `IEND` chunk, with invalid
  `IEND` CRCs rejected as malformed boundaries.
- Current-analysis download selection using deterministic payload IDs for
  same-name recovered byte streams emitted by the current analyzers.

The practical handoff state is:

- The checked-in JPEG and PNG container-side-channel source evidence is present.
- Rust analyzer tests for that package are present.
- Payload identity and download disambiguation tests are present for exact-byte
  dedupe, same-name verified-packet and signature-scan payload preservation,
  replaced-result and reattached-result ID rejection, and blank or
  missing-payload ID rejection, plus current-byte download writes.
- WAV PCM LSB source and focused tests are present as pre-transition evidence
  for the next phase.
- The phase transition is still blocked until `npm run build` passes locally.
  A `tsc: not found` result means setup is incomplete, not that source evidence
  failed.

## Latest Recovery Snapshot

July 4, 2026 KST validation-chain recovery review keeps `current_phase` at
`container-side-channels`. The recovered package includes the container
side-channel source evidence, payload-ID download disambiguation, maintained
documentation, dependency-free validators, JPEG structural EOI test evidence,
and a reconciled tracked management policy marker for public handoff. The
validation gap is still the local runtime toolchain: `npm run build` requires
installed Node dependencies for `tsc` and `vite`, and Rust/Tauri checks require
cached or reachable Cargo dependencies before they can execute repository tests.

## Pre-Transition Audio Evidence

`src-tauri/src/domain/analyzer.rs` also defines `WavPcmLsbAnalyzer` for
uncompressed PCM WAV carriers, and `src-tauri/src/domain/analyzer_pipeline.rs`
registers it in the default analyzer set. The focused tests cover verified
packet recovery, signature-only fallback extraction, default pipeline
registration, and unsupported or truncated WAV safety.
The manifest records that evidence as `wav-pcm-lsb-pretransition-evidence` with
`required_for_transition: false` so reviewers can see the next-phase source
package without treating it as a current-phase transition.

This evidence does not move `current_phase` by itself. The phase state stays
`container-side-channels` until the manifest transition validation command and
required gate review pass locally.

## Source Evidence

Use these checked-in source locations when reviewing the phase:

| Gate | Evidence |
| --- | --- |
| JPEG segment analyzer exists | `src-tauri/src/domain/analyzer.rs` defines `JpegSegmentAnalyzer` and `extract_jpeg_segment_payloads`; `src-tauri/src/domain/analyzer_pipeline.rs` registers `JpegSegmentAnalyzer`. |
| PNG deep container scan exists | `src-tauri/src/domain/analyzer.rs` defines `PngContainerAnalyzer`, `extract_png_container_payloads`, `png_metadata_payload_views`, `decoded_ztxt_text`, `itxt_text_payload`, and `png_after_iend_payload`; `src-tauri/src/domain/analyzer_pipeline.rs` registers `PngContainerAnalyzer`. |
| Analyzer package tests exist | `src-tauri/src/domain/analyzer.rs` includes PNG compressed text, same-name packet preservation, default-pipeline container-side-channel packet extraction, missing or invalid structural IEND rejection, after-IEND, JPEG COM/APP, corrupt packet magic decoy recovery, APP0/APP15 boundary segment, non-payload marker segment exclusion, after-EOI, structural EOI requirement before JPEG segment payload extraction, scan-data isolation, marker-shaped scan-data isolation, byte-stuffed SOS EOI isolation, SOS restart/fill marker isolation, malformed SOS marker recovery, malformed SOS false-EOI length recovery, post-SOS marker-segment skipping, same-name segment/after-EOI preservation, malformed-segment, and non-JPEG/truncated input safety tests. |
| Local-file boundary evidence exists | `src/App.tsx` and `src/api/analysis.ts` send selected media paths through `attach_media_file_from_path`; `src-tauri/src/lib.rs` reads bytes inside Rust and includes `attach_media_file_from_path_command_test_reads_local_media_path`. |
| Payload ID download disambiguation exists | `src-tauri/src/domain/analyzer_pipeline.rs` assigns deterministic payload IDs from analyzer name, embedded file name, file type, payload source, and recovered bytes; `src-tauri/src/domain/task.rs` stores payload bytes with metadata; `src-tauri/src/lib.rs` resolves payload IDs against the current analysis result before downloading, including same-name JPEG segment and after-EOI payload command tests; `src/App.tsx` and `src/api/analysis.ts` pass `file.id` through the frontend IPC wrapper. |
| WAV PCM LSB pre-transition evidence exists | `docs/instructions/phase-gates.json` declares `wav-pcm-lsb-pretransition-evidence` as informational; `src-tauri/src/domain/analyzer.rs` defines `WavPcmLsbAnalyzer`, `wav_pcm_data`, `extract_wav_pcm_lsb_bits`, and focused WAV tests; `src-tauri/src/domain/analyzer_pipeline.rs` registers `WavPcmLsbAnalyzer`. |
| Frontend build gate exists | `package.json` defines `scripts.build` as `tsc && vite build`. |

## Gate Verification Runbook

Use this runbook before opening a phase-transition patch. It maps the machine
gates in `docs/instructions/phase-gates.json` to local repository evidence and
the command that proves the evidence still holds.

| Gate | Check | Validation |
| --- | --- | --- |
| `jpeg-segment-analyzer-exists` | Confirm `src-tauri/src/domain/analyzer.rs` still defines `JpegSegmentAnalyzer`, `extract_jpeg_segment_payloads`, `jpeg_payload_segments`, and `jpeg_after_eoi_payload`; confirm `src-tauri/src/domain/analyzer_pipeline.rs` still registers `JpegSegmentAnalyzer` in `default_analyzers()`. | `cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer` |
| `png-deep-container-scan-exists` | Confirm `src-tauri/src/domain/analyzer.rs` still defines `PngContainerAnalyzer`, `extract_png_container_payloads`, `png_metadata_payload_views`, `decoded_ztxt_text`, `itxt_text_payload`, and `png_after_iend_payload`; confirm `src-tauri/src/domain/analyzer_pipeline.rs` still registers `PngContainerAnalyzer` in `default_analyzers()`. | `cargo test --manifest-path src-tauri/Cargo.toml png_container_analyzer` plus `cargo test --manifest-path src-tauri/Cargo.toml compressed_png` |
| `rust-analyzer-tests-exist` | Confirm the named manifest evidence tests still exist: compressed PNG text extraction, same-name packet preservation, default-pipeline container-side-channel packet extraction, PNG after-IEND extraction, JPEG COM/APP extraction, corrupt packet magic decoy recovery, APP0/APP15 boundary segment coverage, non-payload marker segment exclusion, JPEG after-EOI extraction, structural EOI requirement before JPEG segment payload extraction, scan-data isolation, marker-shaped scan-data isolation, byte-stuffed SOS EOI isolation, SOS restart/fill marker isolation, malformed SOS marker recovery, malformed SOS false-EOI length recovery, post-SOS marker-segment skipping, same-name segment/after-EOI preservation, malformed segment handling, and non-JPEG/truncated input safety. | `cargo test --manifest-path src-tauri/Cargo.toml` |
| `local-file-boundary-evidence` | Confirm the frontend wrapper still sends the selected local media path through `attach_media_file_from_path`, and Rust still reads the file bytes inside the command boundary. | `cargo test --manifest-path src-tauri/Cargo.toml attach_media_file_from_path_command_test_reads_local_media_path` |
| `payload-id-download-disambiguation` | Confirm exact duplicate payload records collapse, distinct same-name verified-packet and signature-scan byte streams keep separate IDs, JPEG segment and after-EOI same-name payloads keep separate downloadable IDs, blank, missing, replaced-result, or reattached-result stale payload IDs are rejected against the current result, the frontend passes `file.id`, and downloads write the bytes for the selected current payload ID. | `npm run validate:download-ipc` plus the payload identity commands in [Testing And Validation](testing.md#recommended-validation-by-change-type). |
| `wav-pcm-lsb-pretransition-evidence` | Confirm the next-phase WAV PCM LSB source symbols, default registry entry, and focused test names remain visible while `current_phase` stays unchanged. | `cargo test --manifest-path src-tauri/Cargo.toml wav_pcm_lsb` |
| `frontend-build-passes` | Confirm the frontend still compiles through the checked-in `build` script. This is the transition command and must be fresh for a phase change. | `npm run build` |

For a dependency-free static pass across the phase model, manifest, maintained
docs, JPEG/PNG source names, named Rust analyzer test functions, local-file
boundary evidence, build-script gate, payload-ID download contract, and
informational WAV PCM LSB pre-transition evidence, run
`npm run validate:phase-evidence`. This command is useful when local dependency
setup is blocked, but it does not replace `npm run build` or Rust analyzer tests
for a phase-transition patch.

`npm run validate:toolchain-readiness` classifies local dependency setup blockers
before the transition command by checking the local TypeScript/Vite binaries and
offline Cargo metadata resolution. It is a setup preflight, not transition
evidence, and does not advance phase state.

Recommended order:

1. Install local Node dependencies from the checked-in lockfile if
   `node_modules/` is missing: `npm ci`.
2. Run `npm run validate:toolchain-readiness` if local setup is uncertain.
   Stop if it reports blockers; do not change phase state.
3. Run `npm run build`. Stop if this fails; do not change phase state.
4. Run the focused JPEG and PNG Rust analyzer tests when reviewing only the
   current phase evidence.
5. Run the full Rust test command before a phase-transition patch or after any
   analyzer behavior changes.

For a generic documentation-only pass, `git diff --check` is sufficient
validation of edited Markdown files. When phase handoff docs or local validator
guidance changes, also run `npm run validate:static`. When
`docs/instructions/phase-gates.json` changes, also run
`python3 -m json.tool docs/instructions/phase-gates.json`. These checks are not
transition evidence. A phase-transition patch must include a fresh
`npm run build` result and should include the Rust analyzer test result when
analyzer evidence has changed since the last review.

## Transition Boundary

Do not move `current_phase` to `audio-lsb-analysis` until:

1. `npm run build` passes in a checkout with Node dependencies installed.
2. `cargo test --manifest-path src-tauri/Cargo.toml` passes after any system
   tooling blocker is resolved. A blocked Rust validation run can be documented,
   but it must not advance `current_phase`.
3. The required evidence in `docs/instructions/phase-gates.json` still matches
   the source after any analyzer changes.

The next phase is intentionally narrower than the full media-analysis catalog.
Its source package now exists as a focused WAV PCM sample LSB analyzer with Rust
tests. The current desktop attach path already sends a selected local path to
Rust and lets Rust read the file bytes; later ingestion work should focus on
hardening that boundary, command validation, and retiring the legacy byte-input
compatibility command when no caller needs it.

## Remaining Implementation Work

The checked-in `container-side-channels` source gates are present, and the WAV
PCM sample LSB source/test package now exists as pre-transition audio evidence.
The next immediate handoff is validation, not another analyzer rewrite: install
the local frontend dependencies, rerun the transition command, and only then
prepare a phase-transition patch if every required gate still matches source.
The payload ID download contract is now included in that gate review because
same-name recovered byte streams can be emitted by the current container
analyzers.
The ingestion boundary now has implementation evidence: the current frontend
attach wrapper sends a selected local media path, and Rust reads file bytes
inside `attach_media_file_from_path`. The legacy byte-input command remains
registered for compatibility and command-level coverage, so later cleanup can
remove that surface once no caller needs it.

Do not use this documentation note to advance phase state. Phase state still
needs a passing transition validation run, even when implementation evidence for
individual source gates is present.

## Documentation Handoff Note

This document is the maintained handoff for the current analyzer phase. It
connects the machine-readable phase gates to checked-in source evidence, names
the exact validation commands for each gate, and records the remaining boundary
before `audio-lsb-analysis`.

The handoff does not replace source or test evidence. Updating this note without
a passing transition validation run does not advance `current_phase`.

## Known Local Validation Blockers

Fresh phase validation can be blocked by local setup rather than repository
behavior:

- `npm run build` reports `tsc: not found` when `node_modules/` has not been
  installed.
- `npm ci` can fail before dependency installation when the machine cannot
  resolve `registry.npmjs.org`.
- Rust/Tauri checks can fail before project checks when Cargo cannot resolve
  `index.crates.io`.
- Rust/Tauri checks can fail on Linux before project checks when `pkg-config` or
  GLib development metadata is missing.

Resolve those environment blockers outside the repository. Do not change
dependency manifests, lockfiles, source code, or phase state only to work around
local setup. When validation is blocked, record the date, exact command, exact
error, and whether the failure happened before repository code was checked. See
[Troubleshooting](troubleshooting.md) for npm and Rust/Tauri blocker details.

Current automation context for this documentation handoff:

- June 16, 2026 phase-controller check: `npm run build` stopped before
  TypeScript compilation with `sh: 1: tsc: not found`. That is consistent with
  missing local Node dependencies.
- June 16, 2026 dependency setup attempts:
  `npm ci --offline --cache /tmp/stegascope-home-npm-cache` could not complete
  because `yallist-3.1.1.tgz` was not cached, and
  `npm ci --prefer-offline --cache /tmp/stegascope-home-npm-cache` could not
  complete because package tarball fetches from `registry.npmjs.org`
  repeatedly reported `EAI_AGAIN`, then npm exited with
  `Exit handler never called!`.
- June 17, 2026 recovery validation reproduced the setup blocker:
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache` repeatedly hit
  `EAI_AGAIN` package fetch failures and npm exited with
  `Exit handler never called!`; `npm ci --offline --ignore-scripts` failed
  because `yallist-3.1.1.tgz` was not cached; Cargo offline validation failed
  before project code because the `tauri` crate was not cached.
- June 17, 2026 pending-patch recovery validation reproduced the blocker again:
  `npm run build` stopped at `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache` failed
  because `yallist-3.1.1.tgz` was not cached;
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache` repeatedly hit
  `EAI_AGAIN` package fetch failures from `registry.npmjs.org` and exited with
  `Exit handler never called!`; `cargo check --manifest-path src-tauri/Cargo.toml`
  and `cargo test --manifest-path src-tauri/Cargo.toml` failed before project
  code because Cargo could not resolve `index.crates.io` while fetching the
  `image` crate.
- June 18, 2026 pending-patch recovery validation still could not pass the
  transition gate locally: `npm run build` stopped at `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache` failed
  because `yallist-3.1.1.tgz` was not cached; `npm ci --ignore-scripts --cache
  /tmp/stegascope-npm-cache` repeatedly hit `EAI_AGAIN` package fetch failures
  from `registry.npmjs.org` and exited with `Exit handler never called!`;
  `cargo test --manifest-path src-tauri/Cargo.toml --offline` failed before
  project code because the `tauri` crate was not cached; and online
  `cargo test --manifest-path src-tauri/Cargo.toml` failed before project code
  because Cargo could not resolve `index.crates.io` while fetching the `image`
  crate. Static review repaired the local `TempDir` helper used by command
  tests and added JPEG malformed SOS marker recovery coverage, but these fixes
  still need a dependency-installed Rust test run.
- June 18, 2026 later recovery validation reproduced the same setup blocker:
  `npm run build` stopped at `sh: 1: tsc: not found`; `npm ci --ignore-scripts
  --cache /tmp/stegascope-npm-cache` attempted to fetch uncached tarballs such
  as `typescript-5.8.3.tgz`, `vite-7.3.5.tgz`, and `yallist-3.1.1.tgz`, but
  each registry fetch failed with `EAI_AGAIN` before npm exited with `Exit
  handler never called!`; `cargo test --manifest-path src-tauri/Cargo.toml
  jpeg_segment_analyzer` failed before project tests because Cargo could not
  resolve `index.crates.io` while fetching the `image` crate.
- June 18, 2026 payload-ID gate recovery added the missing phase/runbook
  evidence for same-name download disambiguation. Static validation passed
  with `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`, but runtime validation stayed blocked: `npm run build`
  stopped at `sh: 1: tsc: not found`, and
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache --prefer-offline`
  could not complete because registry tarball fetches failed with `EAI_AGAIN`.
- June 18, 2026 later payload-ID gate recovery added the missing negative
  missing-payload command test to the phase evidence and runbook. Static
  validation passed with `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`, but runtime validation still stopped before repository
  code: `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache --prefer-offline --no-audit --fund=false`
  attempted uncached package tarballs such as `typescript-5.8.3.tgz`,
  `vite-7.3.5.tgz`, `react-19.2.4.tgz`, and `yallist-3.1.1.tgz`, then failed
  with repeated `EAI_AGAIN` registry errors before npm exited with
  `Exit handler never called!`;
  `cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids --offline`
  failed before project code because the `tauri` crate was not cached; and
  `CARGO_HTTP_TIMEOUT=10 CARGO_NET_RETRY=0 cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- June 19, 2026 pending-patch recovery rechecked the same payload-ID gate.
  Static validation passed with `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`; read-only source, test, docs, and frontend review found
  no blocking gap. Runtime validation still stopped before repository code:
  `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache --prefer-offline --no-audit --fund=false`
  attempted uncached package tarballs including `typescript-5.8.3.tgz`,
  `vite-7.3.5.tgz`, `react-19.2.4.tgz`, and `yallist-3.1.1.tgz`, then failed
  with repeated `EAI_AGAIN` registry errors before npm exited with
  `Exit handler never called!`; `cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids --offline --no-run`
  failed before project code because the `tauri` crate was not cached; and
  `CARGO_HTTP_TIMEOUT=10 CARGO_NET_RETRY=0 cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- June 19, 2026 later payload-ID gate recovery added command-level coverage
  for rejecting a stale payload ID after media reattach and reanalysis. Static
  validation passed with `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`, but runtime validation still stopped before repository
  code: `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache --prefer-offline --no-audit --fund=false`
  attempted uncached package tarballs including `vite-7.3.5.tgz`,
  `react-19.2.4.tgz`, `react-dom-19.2.4.tgz`, and `typescript-5.8.3.tgz`,
  then failed with repeated `EAI_AGAIN` registry errors before npm exited with
  `Exit handler never called!`;
  `cargo test --manifest-path src-tauri/Cargo.toml analyze_and_download_command_test_rejects_payload_id_after_reattach --offline --no-run`
  failed before project code because the `tauri` crate was not cached; and
  `CARGO_HTTP_TIMEOUT=10 CARGO_NET_RETRY=0 cargo test --manifest-path src-tauri/Cargo.toml analyze_and_download_command_test_rejects_payload_id_after_reattach --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- June 19, 2026 dependency-free IPC contract validation added
  `npm run validate:download-ipc` and confirmed the frontend sends `file.id`
  while Rust resolves downloads by current payload ID. Static validation passed
  with `npm run validate:download-ipc`,
  `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation remained blocked before source checks:
  `npm run build` stopped at `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  failed because `yallist-3.1.1.tgz` was not cached; the bounded non-offline
  npm retry hit repeated `EAI_AGAIN` registry fetch failures before timing out;
  `cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids --offline --no-run`
  failed because the `tauri` crate was not cached; and the non-offline Cargo
  retry failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- June 19, 2026 later dependency-free phase evidence validation added
  `npm run validate:phase-evidence`, expanded `npm run validate:download-ipc`
  to prove payload evidence symbols still exist in source, and confirmed the
  analyzer-local outcome path plus Tauri handler registration. Static
  validation passed with `npm run validate:download-ipc`,
  `npm run validate:phase-evidence`,
  `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --locked --offline --no-deps --format-version=1`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation remained blocked before source checks:
  `npm run build` stopped at `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  failed because `yallist-3.1.1.tgz` was not cached;
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache --prefer-offline --no-audit --fund=false`
  hit repeated `EAI_AGAIN` registry fetch failures for uncached tarballs such
  as `typescript-5.8.3.tgz`, `vite-7.3.5.tgz`, `react-19.2.4.tgz`, and
  `yallist-3.1.1.tgz`, then npm exited with `Exit handler never called!`; and
  `cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids --offline --no-run`
  failed before project code because the `tauri` crate was not cached.
- June 20, 2026 pending-patch recovery rechecked the same package with the
  dependency-free static gates. Static validation passed with
  `npm run validate:download-ipc`, `npm run validate:phase-evidence`,
  `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation still stopped before repository
  source checks: `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts` failed because `yallist-3.1.1.tgz` was
  not cached; `npm ci --prefer-offline --ignore-scripts --cache
  /tmp/stegascope-npm-cache --fetch-retries=1 --fetch-timeout=10000` hit
  repeated `EAI_AGAIN` registry fetch failures and npm exited with
  `Exit handler never called!`; `cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids --offline --no-run`
  failed before project code because the `tauri` crate was not cached; and
  `CARGO_HTTP_TIMEOUT=10 CARGO_NET_RETRY=0 cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- June 21, 2026 pending-patch recovery hardened the dependency-free evidence
  chain: `validate:download-ipc` now guards frontend download callsites and
  validator imports, `validate:phase-evidence` now checks phase-model drift and
  validator imports, and JPEG SOS restart/fill marker coverage was added to the
  phase evidence list. Static validation passed with
  `npm run validate:download-ipc`, `npm run validate:phase-evidence`,
  `node --check` for both validator scripts,
  `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation still stopped before repository code:
  `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  failed because `yallist-3.1.1.tgz` was not cached; the bounded non-offline
  `npm ci` retry hit repeated `EAI_AGAIN` registry fetch failures for uncached
  tarballs including `typescript-5.8.3.tgz`, `vite-7.3.5.tgz`, `react-19.2.4.tgz`,
  and `yallist-3.1.1.tgz`; `cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --offline --no-run`
  failed before project code because the `tauri` crate was not cached; and
  `CARGO_HTTP_TIMEOUT=10 CARGO_NET_RETRY=0 cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- June 21, 2026 later pending-patch recovery extended
  `validate:phase-evidence` to guard README and phase-readiness handoff drift
  for the active phase, next phase, and `npm run build` transition boundary.
  Static validation passed with `npm run validate:download-ipc`,
  `npm run validate:phase-evidence`, `node --check` for both validator scripts,
  `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation still stopped before repository code:
  `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  failed because `yallist-3.1.1.tgz` was not cached; the bounded non-offline
  `npm ci` retry hit repeated `EAI_AGAIN` registry fetch failures for uncached
  tarballs including `typescript-5.8.3.tgz`, `vite-7.3.5.tgz`,
  `react-19.2.4.tgz`, and `yallist-3.1.1.tgz` before npm exited with
  `Exit handler never called!`; `cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --offline --no-run`
  failed before project code because the `tauri` crate was not cached; and
  `CARGO_HTTP_TIMEOUT=10 CARGO_NET_RETRY=0 cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- June 22, 2026 pending-patch recovery added `npm run validate:static` as the
  dependency-free syntax and evidence validator chain. Static validation passed
  with `npm run validate:static`, `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation still stopped before repository code:
  `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  failed because `yallist-3.1.1.tgz` was not cached; the bounded non-offline
  `npm ci` retry hit repeated `EAI_AGAIN` registry fetch failures for uncached
  tarballs including `typescript-5.8.3.tgz`, `vite-7.3.5.tgz`,
  `react-19.2.4.tgz`, and `yallist-3.1.1.tgz` before npm exited with
  `Exit handler never called!`; `cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --offline --no-run`
  failed before project code because the `tauri` crate was not cached; and
  `CARGO_HTTP_TIMEOUT=10 CARGO_NET_RETRY=0 cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- June 22, 2026 later pending-patch recovery extended
  `validate:phase-evidence` to guard architecture, onboarding, maintenance,
  testing, and troubleshooting handoff drift for the runtime boundary, analyzer
  registry, payload-ID download contract, and setup-blocker guidance. Static
  validation passed with `npm run validate:static` (63 download IPC checks and
  146 phase evidence checks), `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation still stopped before repository code:
  `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  failed because `yallist-3.1.1.tgz` was not cached; the bounded non-offline
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache --prefer-offline --no-audit --fund=false --fetch-retries=1 --fetch-timeout=10000`
  retry hit repeated `EAI_AGAIN` registry fetch failures for uncached tarballs
  including `yallist-3.1.1.tgz`, `vite-7.3.5.tgz`,
  `typescript-5.8.3.tgz`, `react-dom-19.2.4.tgz`, and
  `react-19.2.4.tgz` before npm exited with `Exit handler never called!`;
  `cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --offline --no-run`
  failed before project code because the `tauri` crate was not cached; and
  `CARGO_HTTP_TIMEOUT=10 CARGO_NET_RETRY=0 cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- June 22, 2026 later dependency-free recovery tightened static evidence checks:
  `validate:phase-evidence` now requires named analyzer test evidence to be
  present as Rust `#[test] fn` definitions, and `validate:download-ipc` applies
  the same requirement to payload identity and download command test evidence.
  Static validation passed with `npm run validate:static` (78 download IPC
  checks and 151 phase evidence checks),
  `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation still stopped before repository source
  checks: `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --prefer-offline --no-audit --fund=false --cache /tmp/stegascope-npm-cache --loglevel verbose`
  hit repeated `EAI_AGAIN` registry fetch failures for uncached tarballs
  including `yallist-3.1.1.tgz`, `vite-7.3.5.tgz`, `typescript-5.8.3.tgz`,
  and `react-19.2.4.tgz` before npm exited with `Exit handler never called!`;
  and `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --format-version=1`
  failed before project code because the `tauri` crate was not cached.
- June 22, 2026 UTC / June 23 KST dependency-free recovery added static WAV
  pre-transition evidence checks: `validate:phase-evidence` now guards the
  `WavPcmLsbAnalyzer` source helpers, default registry wiring, and focused WAV
  `#[test] fn` evidence while `docs/testing.md` uses the broader
  `wav_pcm_lsb` cargo filter that also catches the default pipeline WAV test.
  Static validation passed with `npm run validate:static` (78 download IPC
  checks and 160 phase evidence checks),
  `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation still stopped before repository source
  checks: `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  failed because `yallist-3.1.1.tgz` was not cached;
  `npm ci --prefer-offline --no-audit --fund=false --cache /tmp/stegascope-npm-cache --fetch-retries=1 --fetch-timeout=10000`
  hit repeated `EAI_AGAIN` registry fetch failures for uncached tarballs
  including `vite-7.3.5.tgz`, `typescript-5.8.3.tgz`, `yallist-3.1.1.tgz`,
  and `react-19.2.4.tgz` before npm exited with `Exit handler never called!`;
  and `cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --offline --no-run`
  failed before project code because the `tauri` crate was not cached.
- June 23, 2026 KST pending-patch recovery made the dependency-free phase
  evidence manifest-driven for WAV pre-transition review by adding the
  informational `wav-pcm-lsb-pretransition-evidence` gate with
  `required_for_transition: false`, and added
  `default_pipeline_extracts_container_side_channel_packets_from_registered_analyzers`
  to the current-phase Rust analyzer evidence. Static validation passed with
  `npm run validate:static` (78 download IPC checks and 169 phase evidence
  checks), `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation still stopped before repository source
  checks: `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --prefer-offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false --fetch-retries=1 --fetch-timeout=10000`
  hit repeated `EAI_AGAIN` registry fetch failures for uncached tarballs such
  as `yallist-3.1.1.tgz`, `typescript-5.8.3.tgz`, `vite-7.3.5.tgz`,
  `react-dom-19.2.4.tgz`, and `react-19.2.4.tgz` before npm exited with
  `Exit handler never called!`; and
  `cargo test --manifest-path src-tauri/Cargo.toml default_pipeline_extracts_container_side_channel_packets_from_registered_analyzers --offline --no-run`
  failed before project code because the `tauri` crate was not cached.
- June 23, 2026 UTC / June 24 KST pending-patch recovery revalidated the
  recovered container-side-channel and payload-ID download package without
  changing phase state. Static validation passed with `npm run validate:static`
  (80 download IPC checks and 169 phase evidence checks),
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime transition validation still stopped before
  repository source checks: `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --prefer-offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  hit repeated `EAI_AGAIN` registry fetch failures for uncached tarballs such
  as `typescript-5.8.3.tgz`, `vite-7.3.5.tgz`, `react-19.2.4.tgz`,
  `react-dom-19.2.4.tgz`, and `yallist-3.1.1.tgz` before npm exited with
  `Exit handler never called!`.
- June 24, 2026 KST pending-patch recovery preserved the recovered
  container-side-channel, payload-ID download, and dependency-free evidence
  package while tightening the blocker record for review. Static validation
  passed with `npm run validate:static` (80 download IPC checks and 215 phase
  evidence checks), `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  `python3 -m json.tool docs/instructions/phase-gates.json`, and
  `git diff --check`. Runtime validation still stopped before repository source
  checks: `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache --prefer-offline --no-audit --fund=false`
  hit repeated `EAI_AGAIN` registry fetch failures for uncached tarballs
  including `yallist-3.1.1.tgz`, `vite-7.3.5.tgz`, `typescript-5.8.3.tgz`,
  `react-19.2.4.tgz`, and `react-dom-19.2.4.tgz` before npm exited with
  `Exit handler never called!`;
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  failed because `yallist-3.1.1.tgz` was not cached;
  `cargo test --manifest-path src-tauri/Cargo.toml --offline --no-run` failed
  before project code because the `tauri` crate was not cached; and
  `cargo test --manifest-path src-tauri/Cargo.toml assign_payload_ids --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- July 1, 2026 KST pending-patch recovery preserved the recovered
  container-side-channel and payload-ID package while reconciling tracked
  management policy docs with ignored private operator files. Static validation
  passed with `npm run validate:static` (80 download IPC checks and 215 phase
  evidence checks), `cargo fmt --check --manifest-path src-tauri/Cargo.toml`,
  `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  and `git diff --check`. Runtime validation still stopped before repository
  source checks: `npm run build` reported `sh: 1: tsc: not found`;
  `npm ci --prefer-offline --no-audit --fund=false` failed with npm
  `Exit handler never called!` before writing logs; and
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache --prefer-offline --no-audit --fund=false`
  failed with the same npm exit-handler error while writing its log under the
  temporary cache. `cargo test --manifest-path src-tauri/Cargo.toml --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.
- July 3, 2026 KST validation-chain drift repair refreshed the dependency-free
  phase evidence snapshot without changing phase state. Static validation
  passed with `npm run validate:static` (80 download IPC checks and 221 phase
  evidence checks), `cargo metadata --manifest-path src-tauri/Cargo.toml --locked --offline --no-deps --format-version=1`,
  and `git diff --check`. Runtime transition validation still requires local
  Node dependencies before `npm run build` can run the checked-in TypeScript and
  Vite toolchain.
- July 4, 2026 KST validation-chain handoff refresh rechecked the current
  container-side-channel package and added static evidence for same-name JPEG
  payload preservation across segment and after-EOI channels plus structural
  EOI-before-segment coverage without changing phase state. Static
  validation passed with `npm run validate:static` (86 download IPC checks and
  242 phase evidence checks). `npm run validate:toolchain-readiness` reported
  local setup blockers for missing local `tsc`/`vite` binaries and confirmed
  offline Cargo metadata resolution. Runtime transition validation still stopped before
  repository source checks: `npm run build` reported `sh: 1: tsc: not found`,
  `npm ci --offline --ignore-scripts --cache /tmp/stegascope-npm-cache --no-audit --fund=false`
  failed because `yallist-3.1.1.tgz` was not cached,
  `npm ci --ignore-scripts --cache /tmp/stegascope-npm-cache --prefer-offline --no-audit --fund=false --fetch-retries=0 --fetch-timeout=10000`
  hit `EAI_AGAIN` registry fetch failures for uncached tarballs including
  `yallist-3.1.1.tgz`, `vite-7.3.5.tgz`, and `typescript-5.8.3.tgz` before npm
  exited with `Exit handler never called!`, and
  `cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer --no-run`
  failed before project code because Cargo could not resolve
  `index.crates.io` while fetching the `image` crate.

The next valid phase-transition attempt should begin with successful dependency
setup and a fresh `npm run build` result.
