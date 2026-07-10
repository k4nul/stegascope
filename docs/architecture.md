# Architecture Notes

This note is the maintained architecture reference for the current StegaScope
implementation. The checked-in class diagram image and SVG are historical
exports; use this document first when reviewing code paths.

## Runtime Boundary

StegaScope is a Tauri 2 desktop app with a React frontend and a Rust backend.
The frontend owns presentation state and user workflow. The Rust backend owns
task storage, media loading, analyzer execution, payload finalization, and
filesystem writes.

The current frontend attach flow uses the Tauri dialog plugin to select a local
media path, then sends that path to Rust through `attach_media_file_from_path`.
Rust rejects non-regular and over-128 MiB paths before opening and bounded
reading, infers canonical media metadata, and owns the loader handoff. The
older byte-input command remains
registered for compatibility and command-level coverage, but the current
frontend wrapper no longer sends large `number[]` media payloads over IPC.

## Frontend Responsibilities

`src/App.tsx` owns the visible case workspace:

- task form and active task tabs,
- media file path selection through the desktop dialog,
- analyze action state,
- result and extracted-payload rendering,
- download action wiring.

`src/api/analysis.ts` is the frontend contract for Tauri commands. It defines
the task, media, analysis result, extracted file, and download response shapes,
then calls the Rust commands through `invoke`.

## Rust Command Surface

`src-tauri/src/lib.rs` registers the command handlers and stores tasks in the
process-local `AppState`. The active commands are:

- `create_task`
- `attach_media_file_from_path`
- `attach_media_file`
- `analyze_task`
- `get_extracted_files`
- `download_extracted_file`
- `bootstrap_status`

Task data is in memory for the running desktop session. Restarting the app
clears tasks and their extracted payload metadata.

## Domain Modules

The Rust domain layer is organized under `src-tauri/src/domain/`:

| Module | Responsibility |
| --- | --- |
| `task.rs` | Case task data, attached loader, extracted file metadata, and recovered payload bytes. |
| `media_file.rs` | Uploaded media metadata used by loaders and command responses. |
| `file_loader.rs` | MIME-prefix routing for image, audio, and video loaders. |
| `analyzer.rs` | Analyzer traits, analyzer implementations, payload extraction helpers, and inline analyzer tests. |
| `analyzer_pipeline.rs` | Default analyzer registry, analyzer execution helper, payload finalization, and duplicate handling. |
| `extracted_file.rs` | Suspicion levels, validation status, file signature metadata, and extracted file response data. |

## Analyzer Pipeline

`default_analyzers()` currently registers image, audio, and byte-oriented analyzers:

- `metadata-analyzer`
- `png-container-analyzer`
- `jpeg-segment-analyzer`
- `embedded-signature-analyzer`
- `lsb-analyzer`
- `lsb-2bpp-analyzer`
- `wav-pcm-lsb-analyzer`

The command flow in `analyze_task` runs those analyzers and passes collected
payload candidates into task replacement. Task replacement finalizes payloads
through `finalize_extracted_payloads` before storing metadata and bytes.
Verified StegaScope packets take priority over signature-only candidates during
finalization. Finalization removes exact duplicate payload records while
preserving distinct recovered byte streams, even when two side-channel packets
report the same embedded file name.

Audio and video files can be attached through their loaders. The audio-specific
LSB analyzer is intentionally narrow: it parses RIFF/WAVE files with
uncompressed PCM `fmt ` and `data` chunks, then extracts sample LSB streams from
8-, 16-, 24-, and 32-bit PCM data. Other audio and video formats still rely on
byte-oriented signature scanning until their own analyzer phases are selected.

## Payload Download Path

Recovered payload bytes stay in Rust task state alongside the displayed
`ExtractedFile` metadata. Each displayed extracted file includes a deterministic
opaque payload identifier derived from the analyzer name, embedded file name,
file type, payload source, and recovered bytes, so same-name payloads remain
independently selectable. The frontend requests a download by task ID, payload
identifier, and target path. Rust accepts the identifier only when a matching
payload exists in the task's current analysis result, creates parent directories
when needed, and writes the exact recovered bytes to a new destination without
overwriting an existing file. Payload identifiers
are not stable external artifact IDs or per-run nonces; an identical payload
identity can produce the same ID in a later analysis.

## Diagram Status

`Stegascope.drawio` and the exported
`docs/stegascope_class_diagram_after_factory.svg` / `.png` files are retained
as historical diagram artifacts. They do not include current analyzer classes
such as `PngContainerAnalyzer` and `JpegSegmentAnalyzer`, and they may miss
command-level tests and future IPC boundary changes. Regenerate the draw.io
source and exports from current code or remove them in a future documentation
cleanup; do not treat them as the source of truth for current architecture.
