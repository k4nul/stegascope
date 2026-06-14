# Analyzer Phase Readiness

This note records the documentation-facing evidence for the current
`container-side-channels` phase and the boundary before `audio-lsb-analysis`.
It is not a phase transition record; `current_phase` stays unchanged until the
manifest validation command passes locally.

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

## Transition Boundary

Do not move `current_phase` to `audio-lsb-analysis` until:

1. `npm run build` passes in a checkout with Node dependencies installed.
2. `cargo test --manifest-path src-tauri/Cargo.toml` passes or any system
   tooling blocker is explicitly resolved and rerun.
3. The required evidence in `docs/instructions/phase-gates.json` still matches
   the source after any analyzer changes.

The next phase is intentionally narrower than the full media-analysis catalog.
It should add WAV PCM sample LSB analysis and focused tests without rewriting the
large-media ingestion path. Rust-side file ingestion remains a later phase.

## Progress Gate Note

This document supports review and handoff only. The local progress dashboard is
driven by concrete repository evidence such as checked-in management files,
analyzer source symbols, Rust tests, build scripts, phase metadata, and IPC
boundary changes. Updating this note without a passing transition validation run
does not advance the project phase or complete the next analyzer package.

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
local setup.
