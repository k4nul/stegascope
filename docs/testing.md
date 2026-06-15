# Testing And Validation

This repository does not currently define npm `test`, npm `lint`, a docs build,
or a Markdown lint configuration. Choose validation commands based on the files
changed.

## Command Matrix

| Scope | Command | Notes |
| --- | --- | --- |
| Frontend or Vite changes | `npm run build` | Runs `tsc && vite build`. |
| Rust or Tauri backend changes | `cargo check --manifest-path src-tauri/Cargo.toml` | Fast Rust/Tauri compile check. |
| Analyzer behavior changes | `cargo test --manifest-path src-tauri/Cargo.toml` | Runs inline Rust unit tests, including analyzer tests. |
| Release packaging | `npm run tauri -- build` | Runs the frontend build through Tauri and creates bundle artifacts. |
| Documentation-only changes | `git diff --check` | Checks whitespace and patch formatting when no docs-specific validator exists. |

`npm install` is setup, not validation. It creates `node_modules/` and should be
run only when dependencies need to be installed locally.

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
- Compressed PNG `zTXt`/`iTXt` metadata payload extraction.
- PNG after-IEND packet and signature candidate extraction.
- JPEG COM/APP segment extraction, structural after-EOI signature extraction,
  malformed segment safety, and scan-data isolation.
- WAV PCM sample LSB packet and signature extraction, plus unsupported or
  truncated WAV safety.
- Two-bit-per-pixel channel and matrix strategies.
- Verified packet payload byte recovery.
- Signature-only candidate suppression when verified packets exist.
- Invalid MP3 candidate rejection.

There are initial command-level Rust tests for attach and analyze command flow.
There are no frontend tests, command-level Rust tests for every Tauri command,
or end-to-end desktop workflow tests yet.

Analyzer fixtures are synthetic inline byte vectors or generated images. Do not
commit real evidence files, recovered private payloads, or generated fixture
artifacts for analyzer coverage.

## Recommended Validation By Change Type

For documentation-only changes:

```bash
git diff --check
```

Documentation-only validation does not satisfy the phase transition gate. Before
changing `current_phase` in `docs/instructions/phase-gates.json`, rerun the
manifest's transition validation command and the Rust analyzer checks that prove
the selected analyzer package. See
[Analyzer Phase Readiness](phase-readiness.md) for the current evidence map.
That document also contains a gate-by-gate runbook for checking the JPEG, PNG,
Rust test, and frontend build evidence before a phase-transition patch.

For frontend UI or IPC wrapper changes:

```bash
npm run build
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
cargo test --manifest-path src-tauri/Cargo.toml wav_pcm_lsb_analyzer
```

The `png_container_analyzer` filter covers after-IEND payload tests. The
`compressed_png` filter covers the compressed `zTXt`/`iTXt` metadata tests that
also support the current PNG phase gate. The `wav_pcm_lsb_analyzer` filter
covers the audio analyzer package without changing phase state by itself.

For release packaging changes or before creating a distributable:

```bash
npm run tauri -- build
```

## Coverage Gaps

Add these before treating the app as a stable MVP:

- Complete command-level tests for `create_task`, `get_extracted_files`, and
  `download_extracted_file`, plus negative-path attach and analyze cases.
- Frontend tests for task creation, media attachment, analyze button state,
  result rendering, error banners, and download dialog behavior.
- Broader test fixtures for supported media classes and known payload examples.
- A documented implementation policy for large media files, because the current
  frontend sends file bytes over Tauri IPC as a `number[]`. The current
  architecture boundary is summarized in [Architecture Notes](architecture.md),
  but the implementation still needs a later Rust-side ingestion phase.
