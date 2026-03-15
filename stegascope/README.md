# StegaScope

StegaScope is a Tauri + React desktop app baseline for building steganography-focused tooling.

## Current Baseline

- Tauri 2 + React 19 + TypeScript 5 stack is wired and running.
- Frontend includes a clean bootstrap dashboard (no template demo UI).
- Rust backend exposes a `bootstrap_status` command to validate app runtime wiring.

## Development

```bash
npm install
npm run tauri dev
```

## Build

```bash
npm run tauri build
```

## Project Layout

- `src/`: React UI and client-side state.
- `src-tauri/src/`: Rust commands and desktop runtime logic.
- `src-tauri/tauri.conf.json`: app window/build configuration.

## Suggested Next Steps

1. Define MVP requirements for the first steganography workflow.
2. Add Rust-side image processing commands and invoke contracts.
3. Split frontend into feature modules (`features/encode`, `features/decode`, etc.).
4. Add test coverage for Rust commands and critical UI flows.
