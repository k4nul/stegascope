# StegaScope Onboarding

Use this guide to orient around the current implementation before changing the
desktop app. The project is still direction-pending, so keep changes aligned with
the existing case-based workflow unless a product direction document says
otherwise.

## Runtime Shape

StegaScope is split across a React frontend and a Rust/Tauri backend:

- `src/main.tsx` mounts the React app.
- `src/App.tsx` owns the visible workspace, tab state, task form, media picker,
  analyzer trigger, result table, and payload download action.
- `src/api/analysis.ts` contains the typed frontend wrappers around Tauri
  commands.
- `src-tauri/src/lib.rs` registers the Tauri commands, owns the in-memory task
  store, and translates between command inputs and domain objects.
- `src-tauri/src/domain/` holds loaders, analyzer implementations, analyzer
  pipeline registration/finalization, task state, media metadata, and
  extracted-file metadata.

The frontend and Rust backend communicate through Tauri IPC. Keep user interface
state and presentation logic in `src/`, and keep file loading, analyzer behavior,
payload bytes, and filesystem writes in `src-tauri/`.

For a maintained architecture summary, including the command surface, domain
module map, analyzer pipeline, and stale diagram status, see
[Architecture Notes](architecture.md).

## Current User Flow

1. Create a task with case number, case name, investigator name, and date.
2. Attach one image, audio, or video file to the task.
3. Run the registered analyzer set.
4. Review confidence, suspicious-region count, analysis note, and extracted file
   rows.
5. Save an extracted payload through the desktop save dialog.

Multiple task tabs can be open in one frontend session. Task data is stored in
memory by the Tauri state object, so it is not persisted across app restarts.

## Command Surface

Registered Rust commands include:

- `create_task`: validates required case fields and creates an in-memory task.
- `attach_media_file_from_path`: validates a selected local media path, reads
  the file in Rust, and creates an image, audio, or video loader from canonical
  media metadata.
- `attach_media_file`: legacy byte-input command used by command-level tests and
  compatibility callers.
- `analyze_task`: runs the default analyzer set and replaces the task's extracted
  files with the latest payload candidates.
- `get_extracted_files`: returns the extracted file metadata for a task.
- `download_extracted_file`: writes a selected extracted payload to the chosen
  target path.
- `bootstrap_status`: reports app/package status.

The frontend wrappers in `src/api/analysis.ts` currently cover the user-facing
commands except `bootstrap_status` and the legacy byte-input attach command.

When adding a new command, update both `src/api/analysis.ts` and the
`tauri::generate_handler!` list in `src-tauri/src/lib.rs`.

## Media Loading

Media type routing is based on MIME-like prefixes:

- `image/*` uses the image loader.
- `audio/*` uses the audio loader.
- `video/*` uses the video loader.

Rust infers a media type from common file extensions when no explicit media type
is supplied. Unsupported extensions fall back to `application/octet-stream`,
which the loader rejects because there is no generic binary loader.

Audio and video files are loadable carrier types. WAV files with uncompressed
PCM sample data are scanned for sample LSB payloads, while other non-image
carriers can still be processed by byte-oriented analyzers such as embedded
signature scanning.

## Analyzer Set

`src-tauri/src/domain/analyzer_pipeline.rs` owns the default analyzer registry
and cross-analyzer payload finalization. `default_analyzers()` currently
registers:

- `metadata-analyzer`: scans PNG metadata and tagged side channels, including
  compressed `zTXt` and `iTXt` text payloads.
- `png-container-analyzer`: scans payload bytes appended after the structural
  PNG `IEND` chunk.
- `jpeg-segment-analyzer`: scans marker-delimited JPEG COM/APP segment data and
  payload bytes appended after the structural EOI marker while skipping scan
  image data.
- `embedded-signature-analyzer`: searches for known embedded file signatures
  after the media header.
- `lsb-analyzer`: extracts RGB least-significant-bit streams from decoded images.
- `lsb-2bpp-analyzer`: extracts two-bit-per-pixel strategies, including
  channel-pair and matrix-order variants.
- `wav-pcm-lsb-analyzer`: extracts least-significant-bit streams from 8-, 16-,
  24-, and 32-bit uncompressed PCM WAV sample data.

The JPEG and PNG container-side-channel coverage is the current phase evidence.
WAV PCM sample LSB source and tests now exist, but the machine-readable phase
state remains unchanged until the transition validation gate passes.

Verified StegaScope packets are preferred over signature-only candidates during
finalization. Extracted payload metadata and payload bytes are tracked together
so the UI can show metadata and later save the exact recovered bytes.

## Development Entry Points

Use these files first when investigating changes:

- UI workflow: `src/App.tsx`
- IPC type contract: `src/api/analysis.ts`
- Command handlers and task store: `src-tauri/src/lib.rs`
- Analyzer registry and finalization: `src-tauri/src/domain/analyzer_pipeline.rs`
- Analyzer behavior and tests: `src-tauri/src/domain/analyzer.rs`
- Loader routing: `src-tauri/src/domain/file_loader.rs`
- Tauri dev/build settings: `src-tauri/tauri.conf.json`

## Boundaries To Preserve

- Preserve the Tauri v2 project structure.
- Keep frontend and Rust responsibilities separate.
- Do not enable local automation until the product direction is selected.
- Do not include `../devops` in active automation for this project.
