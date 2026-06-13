# Troubleshooting

This guide covers failures that can be diagnosed from the current repository
behavior.

## Dev Server Does Not Start

`npm run tauri dev` starts Vite through the Tauri `beforeDevCommand` and expects
the frontend at `http://localhost:1420`. Vite is configured with
`strictPort: true`, so startup fails instead of choosing another port when `1420`
is already in use.

If startup fails:

1. Confirm dependencies are installed with `npm install`.
2. Confirm port `1420` is available.
3. Run `npm run build` to separate TypeScript/Vite failures from Tauri runtime
   failures.
4. Run `cargo check --manifest-path src-tauri/Cargo.toml` to check the Rust side.

## File Selection Fails With Unsupported Media Type

The UI accepts image, audio, and video files. The Rust loader supports media
types beginning with:

- `image/`
- `audio/`
- `video/`

When the browser does not provide a MIME type, the frontend infers one from the
file extension. Unknown extensions become `application/octet-stream`, which is
rejected by the loader as an unsupported media type.

Use a file with a known image, audio, or video extension, or add explicit loader
support before accepting generic binary files.

## Attach Media Reports An Empty File

`attach_media_file` rejects empty byte payloads. Confirm the selected file is not
zero bytes and that the desktop file picker returned the intended file.

## Start Analysis Is Disabled

The analyze button requires a created task and an attached media file. Create the
task first, then attach media. Reattaching media clears the previous result for
that task.

## Analysis Returns No Payload Candidates

No candidates can be a valid result. The analyzer note reports that no extracted
payload candidates were found when the registered analyzers do not detect a known
signature, verified StegaScope packet, metadata payload, or supported LSB payload.

For image LSB analysis, the media must decode successfully as an image. For
non-image media, the LSB analyzers return no candidates.

For PNG container analysis, candidates are limited to bytes appended after the
structural `IEND` chunk. Payload-like bytes in malformed or truncated PNG chunks
are ignored.

For JPEG segment analysis, candidates are limited to valid COM/APP segment data
or bytes appended after the structural EOI marker. Payload-like bytes inside
scan image data, malformed segments, or non-JPEG bytes are ignored.

## Task Not Found

Task IDs exist only in the running desktop session. Restarting the app clears the
in-memory task store. Create a new task after restart.

## Download Fails

`download_extracted_file` requires:

- a valid current task ID,
- a file name and analyzer name that match an extracted payload from the latest
  analysis result,
- a non-empty target path, and
- a target path that is not a directory.

The command creates parent directories when needed and writes the recovered
payload bytes to the selected path.

## Release Build Fails

Release packaging runs the frontend build before Tauri bundling. Start with the
lighter commands:

```bash
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
```

Then rerun packaging:

```bash
npm run tauri -- build
```
