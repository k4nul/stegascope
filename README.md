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

The repository is direction-pending. No public CI or release automation
configuration is checked into the tree; validation is manual/local until a
product direction is selected. Checked-in phase guidance lives in
`docs/instructions/phase-gates.json` and is used by local maintainer tooling to
route analyzer-expansion work, while private maintainer overlays, when present,
stay ignored by Git. Documentation should describe the current implementation
without locking in the MVP roadmap.

The active analyzer-expansion phase is `container-side-channels`, with
`audio-lsb-analysis` listed as the next phase. Source and Rust tests for the WAV
PCM LSB analyzer already exist, but the phase should not move forward until a
fresh `npm run build` transition validation passes in a checkout with Node
dependencies installed. See [Analyzer Phase Readiness](docs/phase-readiness.md)
for the gate-by-gate handoff.

Current implementation facts:

- Frontend: React 19, TypeScript 5, and Vite.
- Desktop shell: Tauri 2 with Rust command handlers.
- Analyzer coverage: PNG metadata and ancillary text chunks, including
  compressed `zTXt`/`iTXt` text payloads, PNG after-IEND container payload data,
  embedded file signatures, JPEG COM/APP segment and after-EOI payload data, RGB
  LSB streams, two-bit-per-pixel LSB strategies, WAV PCM sample LSB streams,
  and verified StegaScope packets.
- Audio and video files can be attached through MIME-prefix loaders. WAV files
  with uncompressed PCM sample data are analyzed for sample LSB payloads; other
  non-image carriers still rely on byte-oriented signature scanning until later
  analyzer phases are selected.
- Task state is in memory for the running desktop session.
- Rust analyzer unit tests exist; initial command-level Rust tests cover attach
  and analyze command flow; frontend UI/API flow tests are still missing.

## Documentation Map

- [Onboarding](docs/onboarding.md): app flow, code map, command surface, and
  current architecture boundaries.
- [Testing](docs/testing.md): validation commands, existing coverage, and
  coverage gaps.
- [Troubleshooting](docs/troubleshooting.md): common local development and app
  workflow failures.
- [Maintenance](docs/maintenance.md): automation posture, safe edit boundaries,
  and documentation upkeep notes.
- [Architecture Notes](docs/architecture.md): maintained frontend/Rust boundary,
  command surface, domain module, analyzer pipeline, and diagram status.
- [Analyzer Phase Readiness](docs/phase-readiness.md): checked-in phase
  evidence, gate verification runbook, and the boundary before audio LSB
  analysis.
- `Stegascope.drawio` and `docs/stegascope_class_diagram_after_factory.svg` /
  `.png`: stale historical diagram source and exports. Treat
  [Architecture Notes](docs/architecture.md) as the maintained architecture
  reference until the diagrams are regenerated from current code or removed.

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

For documentation-only changes, use:

```bash
git diff --check
```

This verifies patch formatting only; it does not satisfy the analyzer phase
transition gate.

## Project Layout

- `src/main.tsx`: React entrypoint.
- `src/App.tsx`: case workspace UI and task lifecycle state.
- `src/api/analysis.ts`: typed frontend wrappers around Tauri IPC commands.
- `src-tauri/src/lib.rs`: Tauri command registration, task store, and command
  handlers.
- `src-tauri/src/domain/`: Rust domain modules for loaders, tasks, analyzer
  implementations, analyzer pipeline registration/finalization, extracted
  files, and media file metadata.
- `src-tauri/tauri.conf.json`: Tauri app, dev server, build, bundle, and window
  configuration.

## Suggested Next Steps

1. Select and document the MVP product direction before enabling automation.
2. Produce a fresh `npm run build` transition result before attempting a phase
   transition out of `container-side-channels`; install dependencies and resolve
   local npm, DNS, or cache blockers first if needed.
3. Move large media ingestion closer to Rust so desktop file paths can be read
   without sending full `number[]` payloads over Tauri IPC.
4. Split frontend analysis surfaces into feature modules once the workflow is
   accepted.
5. Add command-level Rust tests and critical UI/API flow coverage.
6. Regenerate the draw.io class diagram and exported images from current code,
   or remove the stale diagram artifacts.
