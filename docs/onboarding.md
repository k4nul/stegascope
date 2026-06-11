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
- `src-tauri/src/domain/` holds loaders, analyzers, task state, media metadata,
  and extracted-file metadata.

The frontend and Rust backend communicate through Tauri IPC. Keep user interface
state and presentation logic in `src/`, and keep file loading, analyzer behavior,
payload bytes, and filesystem writes in `src-tauri/`.

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

The frontend wrappers in `src/api/analysis.ts` call these Rust commands:

- `create_task`: validates required case fields and creates an in-memory task.
- `attach_media_file`: validates task ID, file name, and non-empty bytes; creates
  an image, audio, or video loader from the uploaded media metadata.
- `analyze_task`: runs the default analyzer set and replaces the task's extracted
  files with the latest payload candidates.
- `get_extracted_files`: returns the extracted file metadata for a task.
- `download_extracted_file`: writes a selected extracted payload to the chosen
  target path.
- `bootstrap_status`: reports app/package status, but the current UI does not
  call it.

When adding a new command, update both `src/api/analysis.ts` and the
`tauri::generate_handler!` list in `src-tauri/src/lib.rs`.

## Media Loading

Media type routing is based on MIME-like prefixes:

- `image/*` uses the image loader.
- `audio/*` uses the audio loader.
- `video/*` uses the video loader.

The frontend infers a media type from common file extensions when the browser
does not provide one. Unsupported extensions fall back to
`application/octet-stream`, which the Rust loader rejects because there is no
generic binary loader.

## Analyzer Set

`default_analyzers()` currently registers:

- `metadata-analyzer`: scans PNG metadata and tagged side channels.
- `jpeg-segment-analyzer`: scans JPEG COM/APP segment data and payload bytes
  appended after EOI.
- `embedded-signature-analyzer`: searches for known embedded file signatures
  after the media header.
- `lsb-analyzer`: extracts RGB least-significant-bit streams from decoded images.
- `lsb-2bpp-analyzer`: extracts two-bit-per-pixel strategies, including
  channel-pair and matrix-order variants.

Verified StegaScope packets are preferred over signature-only candidates during
finalization. Extracted payload metadata and payload bytes are tracked together
so the UI can show metadata and later save the exact recovered bytes.

## Development Entry Points

Use these files first when investigating changes:

- UI workflow: `src/App.tsx`
- IPC type contract: `src/api/analysis.ts`
- Command handlers and task store: `src-tauri/src/lib.rs`
- Analyzer behavior and tests: `src-tauri/src/domain/analyzer.rs`
- Loader routing: `src-tauri/src/domain/file_loader.rs`
- Tauri dev/build settings: `src-tauri/tauri.conf.json`

## Boundaries To Preserve

- Preserve the Tauri v2 project structure.
- Keep frontend and Rust responsibilities separate.
- Do not enable local automation until the product direction is selected.
- Do not include `../devops` in active automation for this project.
