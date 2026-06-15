# Analyzer Phase Readiness

This note records the documentation-facing evidence for the current
`container-side-channels` phase and the boundary before `audio-lsb-analysis`.
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
- PNG compressed `zTXt` and `iTXt` text payload scanning.
- PNG payload bytes appended after the structural `IEND` chunk.

## Source Evidence

Use these checked-in source locations when reviewing the phase:

| Gate | Evidence |
| --- | --- |
| JPEG segment analyzer exists | `src-tauri/src/domain/analyzer.rs` defines `JpegSegmentAnalyzer` and `extract_jpeg_segment_payloads`; `src-tauri/src/domain/analyzer_pipeline.rs` registers `JpegSegmentAnalyzer`. |
| PNG deep container scan exists | `src-tauri/src/domain/analyzer.rs` defines `PngContainerAnalyzer`, `extract_png_container_payloads`, `png_metadata_payload_views`, `decoded_ztxt_text`, `itxt_text_payload`, and `png_after_iend_payload`; `src-tauri/src/domain/analyzer_pipeline.rs` registers `PngContainerAnalyzer`. |
| Analyzer package tests exist | `src-tauri/src/domain/analyzer.rs` includes PNG compressed text, after-IEND, JPEG COM/APP, after-EOI, scan-data isolation, and malformed-segment tests. |
| Frontend build gate exists | `package.json` defines `scripts.build` as `tsc && vite build`. |

## Gate Verification Runbook

Use this runbook before opening a phase-transition patch. It maps the machine
gates in `docs/instructions/phase-gates.json` to local repository evidence and
the command that proves the evidence still holds.

| Gate | Check | Validation |
| --- | --- | --- |
| `jpeg-segment-analyzer-exists` | Confirm `src-tauri/src/domain/analyzer.rs` still defines `JpegSegmentAnalyzer`, `extract_jpeg_segment_payloads`, `jpeg_payload_segments`, and `jpeg_after_eoi_payload`; confirm `src-tauri/src/domain/analyzer_pipeline.rs` still registers `JpegSegmentAnalyzer` in `default_analyzers()`. | `cargo test --manifest-path src-tauri/Cargo.toml jpeg_segment_analyzer` |
| `png-deep-container-scan-exists` | Confirm `src-tauri/src/domain/analyzer.rs` still defines `PngContainerAnalyzer`, `extract_png_container_payloads`, `png_metadata_payload_views`, `decoded_ztxt_text`, `itxt_text_payload`, and `png_after_iend_payload`; confirm `src-tauri/src/domain/analyzer_pipeline.rs` still registers `PngContainerAnalyzer` in `default_analyzers()`. | `cargo test --manifest-path src-tauri/Cargo.toml png_container_analyzer` plus `cargo test --manifest-path src-tauri/Cargo.toml compressed_png` |
| `rust-analyzer-tests-exist` | Confirm the named manifest evidence tests still exist: compressed PNG text extraction, PNG after-IEND extraction, JPEG COM/APP extraction, JPEG after-EOI extraction, scan-data isolation, and malformed segment handling. | `cargo test --manifest-path src-tauri/Cargo.toml` |
| `frontend-build-passes` | Confirm the frontend still compiles through the checked-in `build` script. This is the transition command and must be fresh for a phase change. | `npm run build` |

For a documentation-only pass, `git diff --check` is sufficient validation of
the edited files, but it is not transition evidence. A phase-transition patch
must include a fresh `npm run build` result and should include the Rust analyzer
test result when analyzer evidence has changed since the last review.

## Transition Boundary

Do not move `current_phase` to `audio-lsb-analysis` until:

1. `npm run build` passes in a checkout with Node dependencies installed.
2. `cargo test --manifest-path src-tauri/Cargo.toml` passes after any system
   tooling blocker is resolved. A blocked Rust validation run can be documented,
   but it must not advance `current_phase`.
3. The required evidence in `docs/instructions/phase-gates.json` still matches
   the source after any analyzer changes.

The next phase is intentionally narrower than the full media-analysis catalog.
It should add WAV PCM sample LSB analysis and focused tests without rewriting the
large-media ingestion path. Rust-side file ingestion remains a later phase.

## Remaining Implementation Work

The checked-in `container-side-channels` source gates are present, but the next
analyzer package is still implementation work: add WAV PCM sample LSB analysis
with focused Rust tests. A later ingestion phase should also change the current
frontend IPC boundary so large media files are not sent as `number[]` payloads
through `src/api/analysis.ts`.

Do not use this documentation note to mark either item complete. The WAV PCM
gate needs source and test evidence in the Rust analyzer layer, while the IPC
boundary gate needs an implementation change across `src/api/analysis.ts` and
the Tauri command surface.

## Documentation Handoff Note

This document is the maintained handoff for the current analyzer phase. It
connects the machine-readable phase gates to checked-in source evidence, names
the exact validation commands for each gate, and records the remaining boundary
before `audio-lsb-analysis`.

The handoff does not replace source or test evidence. Updating this note without
a passing transition validation run does not advance `current_phase`, implement
WAV PCM LSB analysis, or change the large-media IPC boundary.

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
