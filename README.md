# StegaScope

StegaScope is a Tauri + React desktop app baseline for building steganography-focused tooling.

## Current Baseline

- Tauri 2 + React 19 + TypeScript 5 stack is wired and running.
- Frontend provides a case-based steganalysis workspace for creating tasks,
  attaching media, running analyzers, reviewing extracted files, and saving
  recovered payloads.
- Rust backend exposes task, media attachment, analyzer execution, extracted-file
  lookup, and payload download commands.
- Analyzer coverage includes embedded file-signature scans, RGB LSB streams,
  two-bit-per-pixel LSB strategies, verified StegaScope packets, and PNG
  metadata/ancillary chunk scans.

## Development

```bash
npm install
npm run tauri dev
```

## Build

```bash
npm run tauri -- build
```

## Project Layout

- `src/`: React UI and client-side state.
- `src-tauri/src/`: Rust commands and desktop runtime logic.
- `src-tauri/tauri.conf.json`: app window/build configuration.

## Suggested Next Steps

1. Decide whether the current case-based steganalysis workflow is the MVP
   direction, then update local direction and automation gates accordingly.
2. Move large media ingestion closer to Rust so desktop file paths can be read
   without sending full `number[]` payloads over Tauri IPC.
3. Split frontend analysis surfaces into feature modules once the workflow is
   accepted.
4. Add command-level Rust tests and critical UI/API flow coverage.
