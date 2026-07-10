# Contributing to StegaScope

StegaScope is a Tauri 2 + React desktop application for steganography-focused
analysis workflows. Keep contributions aligned with the current implementation
unless a product direction has been documented first.

## Local Setup

```bash
npm ci
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
```

Run the desktop app locally with:

```bash
npm run tauri dev
```

## Pull Request Checklist

- Keep frontend and Rust/Tauri boundaries clear.
- Avoid committing sample evidence files that may contain private data.
- Add Rust tests for analyzer behavior and command-level changes.
- Update `docs/` when workflows, supported file types, or analyzer results change.
- Keep automation disabled unless the product direction gate is intentionally updated.

## Test Data

Use synthetic fixtures only. Do not commit real case files, private images,
documents, recovered payloads, or user-provided evidence.
