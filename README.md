# StegaScope

StegaScope is a Tauri 2 + React desktop app baseline for steganography-focused
analysis tooling. The current build presents a case-based steganalysis
workspace where an investigator can create a task, attach one media file, run
the registered analyzers, review extracted payload candidates, and save recovered
payload bytes through the desktop shell.

## Open Source

This repository is prepared for public collaboration under the [MIT License](LICENSE).
See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before opening issues or pull requests.
Do not commit real evidence files, recovered private payloads, local app data,
or generated desktop bundles.

## Project Status

The repository is direction-pending. Local automation is prepared but disabled
until a product direction is selected, so documentation should describe the
current implementation without locking in the MVP roadmap.

Current implementation facts:

- Frontend: React 19, TypeScript 5, and Vite.
- Desktop shell: Tauri 2 with Rust command handlers.
- Analyzer coverage: PNG metadata and ancillary text chunks, embedded file
  signatures, RGB LSB streams, two-bit-per-pixel LSB strategies, and verified
  StegaScope packets.
- Task state is in memory for the running desktop session.
- Rust analyzer unit tests exist; command-level Rust tests and frontend UI/API
  flow tests are still missing.

## Documentation Map

- [Onboarding](docs/onboarding.md): app flow, code map, command surface, and
  current architecture boundaries.
- [Testing](docs/testing.md): validation commands, existing coverage, and
  coverage gaps.
- [Troubleshooting](docs/troubleshooting.md): common local development and app
  workflow failures.
- [Maintenance](docs/maintenance.md): automation posture, safe edit boundaries,
  and documentation upkeep notes.
- `docs/stegascope_class_diagram_after_factory.svg` and `.png`: existing class
  diagram exports. Treat them as historical references until regenerated from
  current code.

## Quick Start

Install dependencies:

```bash
npm install
```

Run the desktop app in development:

```bash
npm run tauri dev
```

The Tauri dev configuration starts Vite through `npm run dev` and expects the
frontend at `http://localhost:1420`.

## Validation

Run the checks that match the scope of your change:

```bash
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
```

For release packaging, run:

```bash
npm run tauri -- build
```

See [Testing](docs/testing.md) for when each command is appropriate.

## Project Layout

- `src/main.tsx`: React entrypoint.
- `src/App.tsx`: case workspace UI and task lifecycle state.
- `src/api/analysis.ts`: typed frontend wrappers around Tauri IPC commands.
- `src-tauri/src/lib.rs`: Tauri command registration, task store, and command
  handlers.
- `src-tauri/src/domain/`: Rust domain modules for loaders, tasks, analyzers,
  extracted files, and media file metadata.
- `src-tauri/tauri.conf.json`: Tauri app, dev server, build, bundle, and window
  configuration.
- `.codex/automation.yaml`: prepared but disabled automation gate.
- `AGENTS.md`: local maintainer instructions and validation policy.

## Suggested Next Steps

1. Select and document the MVP product direction before enabling automation.
2. Move large media ingestion closer to Rust so desktop file paths can be read
   without sending full `number[]` payloads over Tauri IPC.
3. Split frontend analysis surfaces into feature modules once the workflow is
   accepted.
4. Add command-level Rust tests and critical UI/API flow coverage.
5. Regenerate the class diagram exports from current code or replace them with a
   source-controlled architecture note.
