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

Rust analyzer unit tests live inline in `src-tauri/src/domain/analyzer.rs`. They
cover representative payload extraction behavior, including:

- RGB LSB extraction from image streams.
- Non-image media ignored by image-only analyzers.
- PNG metadata packet extraction.
- PNG metadata signature candidate extraction.
- JPEG COM packet extraction and after-EOI signature candidate extraction.
- Two-bit-per-pixel channel and matrix strategies.
- Verified packet payload byte recovery.
- Signature-only candidate suppression when verified packets exist.
- Invalid MP3 candidate rejection.

There are initial command-level Rust tests for attach and analyze command flow.
There are no frontend tests, command-level Rust tests for every Tauri command,
or end-to-end desktop workflow tests yet.

## Recommended Validation By Change Type

For documentation-only changes:

```bash
git diff --check
```

For frontend UI or IPC wrapper changes:

```bash
npm run build
```

For Rust command, loader, task, or analyzer changes:

```bash
cargo check --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
```

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
- Test fixtures for supported media classes and known payload examples.
- A documented policy for large media files, because the current frontend sends
  file bytes over Tauri IPC as a `number[]`.
