# Maintenance Notes

StegaScope is currently direction-pending. Keep maintenance work focused on the
implementation that exists today, and avoid enabling automation or committing to
an MVP direction until the product direction is selected.

## Automation State

No public CI or release automation configuration is checked into the tree. The
repository intentionally ignores private local maintainer files:

- `AGENTS.md`
- `.codex/`
- generated `docs/management/` files other than the tracked
  `docs/management/POLICY.json` policy marker

Do not add or track those private files during ordinary documentation, test,
lint, or implementation maintenance. The checked-in policy marker documents
which local management files may exist in operator checkouts without requiring
them in the public handoff. Checked-in phase guidance lives in
`docs/instructions/phase-gates.json` and may be read by local maintainer
tooling, but phase state must not be changed unless the manifest validation
command and required evidence gates pass. Public automation activation still
requires a product direction decision and an explicit tracked configuration in a
future change.

If a local automation report mentions ignored management files from another
checkout, treat them as private context only; the tracked handoff remains this
maintenance note, `docs/instructions/phase-gates.json`, and
`docs/phase-readiness.md`.

## Safe Edit Boundaries

Follow these repository boundaries:

- Preserve the Tauri v2 structure.
- Keep frontend and Rust backend boundaries clear.
- Avoid automation activation.
- Avoid product direction lock-in.
- Do not include `../devops` in active automation until product direction is
  selected.

## Documentation Upkeep

Update documentation when behavior changes in these areas:

- Tauri command names, inputs, outputs, or error messages.
- Frontend task lifecycle or user workflow.
- Analyzer registration, payload finalization, or supported media behavior.
- Validation commands, test coverage, or release packaging behavior.
- Automation activation state or local maintainer instructions.

The maintained architecture reference is
[Architecture Notes](architecture.md). The existing draw.io class diagram and
exports under `docs/` may lag behind the current Rust domain model. Before
using them as architecture references, compare them with `src-tauri/src/domain/`
and regenerate the source plus exports or remove them in a future documentation
cleanup.

For phase evidence and the transition boundary between
`container-side-channels` and `audio-lsb-analysis`, keep
[Analyzer Phase Readiness](phase-readiness.md) in sync with
`docs/instructions/phase-gates.json` and the Rust analyzer registry.

## Validation Policy

Use the narrowest command that matches the touched scope:

- Documentation-only: `git diff --check`
- Phase gate metadata: `python3 -m json.tool docs/instructions/phase-gates.json`
- Dependency-free static recovery chain: `npm run validate:static`
- Toolchain readiness preflight: `npm run validate:toolchain-readiness`
- Phase evidence static review: `npm run validate:phase-evidence`
- Download IPC contract static review: `npm run validate:download-ipc`
- Frontend or Vite changes: `npm run build`
- Rust or Tauri backend changes: `cargo check --manifest-path src-tauri/Cargo.toml`
- Analyzer behavior changes: `cargo test --manifest-path src-tauri/Cargo.toml`
- Release packaging: `npm run tauri -- build`

Document any skipped validation with the exact blocker.

## Current Larger Maintenance Gaps

- Product direction is not selected.
- Automation remains disabled by design.
- Phase transition out of `container-side-channels` still requires a fresh
  `npm run build` result plus the required analyzer evidence gates.
- The next phase handoff is validation-first: install local Node dependencies if
  needed, rerun `npm run build`, and record the result before changing phase
  state. A `tsc: not found` result is a setup blocker, not a repository source
  failure.
- The Rust-side ingestion boundary now has implementation evidence through the
  path-based attach command. Phase state must still wait for a passing
  transition validation run. Do not change phase state with documentation-only
  updates.
- Command-level Rust coverage is partial; create, attach, path-based reattach
  result clearing, analyze, list-extracted-files, download flow, and stale
  payload-ID rejection after reattach/reanalysis have initial tests.
  Attach/analyze negative paths now cover invalid byte input, invalid path input,
  stale task IDs before media loader validation or local path inspection,
  missing tasks, and missing media, while broader cross-command state
  transitions still need coverage.
- Frontend UI/API flow tests are missing.
- Large media handling now uses a path-based frontend attach flow. A later
  cleanup can remove the legacy byte-input attach command after compatibility
  callers are no longer needed.
- The draw.io class diagram and exports need regeneration or removal now that a
  maintained text architecture note exists.
