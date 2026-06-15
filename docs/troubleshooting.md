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

## Frontend Build Reports `tsc: not found`

`npm run build` starts with `tsc && vite build`. If the shell reports
`tsc: not found`, the command stopped before TypeScript checked repository
source. In this repository that usually means local Node dependencies are not
installed in the checkout. Run setup first:

```bash
npm install
```

Then rerun:

```bash
npm run build
```

Do not edit dependency manifests to fix this blocker unless the dependency set
itself is changing.

For phase-transition work, this is a blocker, not passing or failing evidence.
Keep `docs/instructions/phase-gates.json` unchanged until setup succeeds and a
fresh `npm run build` result is available.

If `npm ci` cannot resolve `registry.npmjs.org`, fix network or DNS access and
rerun setup before treating the frontend build as a project failure.

In sandboxed automation runs, npm may also need a writable cache outside the
home directory. Use a temporary cache for setup validation when the default
`~/.npm` path is not writable:

```bash
npm_config_cache=/tmp/stegascope-npm-cache npm ci
```

If that command still reports `EAI_AGAIN` while fetching packages, the blocker is
network or DNS access to `registry.npmjs.org`, not a repository dependency
manifest issue.

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

For WAV audio carriers, uncompressed PCM `fmt ` and `data` chunks are scanned
for sample LSB payload streams. Unsupported WAV encodings, malformed WAV chunks,
and non-WAV audio/video carriers may still be checked by byte-oriented embedded
signature scanning, but they do not run audio-specific LSB extraction.

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

## Rust/Tauri Checks Cannot Find `pkg-config`

`cargo check --manifest-path src-tauri/Cargo.toml` and
`cargo test --manifest-path src-tauri/Cargo.toml` compile the Tauri stack before
running project tests. On Linux, the build can fail in native system crates if
`pkg-config` is missing or cannot find `glib-2.0`.

Install the missing system build tooling outside the repository, then rerun the
Rust command. Do not commit generated `src-tauri/target/` output from failed or
successful local builds.

If the blocked Rust command is being used as phase-transition evidence, update
the validation notes in [Analyzer Phase Readiness](phase-readiness.md) only
after rerunning the command.

If Cargo cannot resolve `index.crates.io`, fix network or DNS access first. That
failure happens before Rust dependency compilation and does not prove whether
project code or system libraries pass.
