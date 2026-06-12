# Maintenance Notes

StegaScope is currently direction-pending. Keep maintenance work focused on the
implementation that exists today, and avoid enabling automation or committing to
an MVP direction until the product direction is selected.

## Automation State

`.codex/automation.yaml` marks automation as prepared but disabled:

- `automation.enabled` is `false`.
- The activation state is `disabled_until_product_direction_is_selected`.
- Jobs for frontend build, Rust check, and Tauri packaging are present but
  disabled.

Do not change those settings during ordinary documentation, test, lint, or
implementation maintenance. Activation requires a product direction decision,
setting `automation.enabled` to `true`, selecting at least one trigger, and
enabling the required jobs.

## Safe Edit Boundaries

Follow the local maintainer policy in `AGENTS.md`:

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

The existing class diagram exports under `docs/` may lag behind the current Rust
domain model. Before using them as architecture references, compare them with
`src-tauri/src/domain/` and regenerate the exports from the diagram source or
replace them with a maintained architecture document.

## Validation Policy

Use the narrowest command that matches the touched scope:

- Documentation-only: `git diff --check`
- Frontend or Vite changes: `npm run build`
- Rust or Tauri backend changes: `cargo check --manifest-path src-tauri/Cargo.toml`
- Analyzer behavior changes: `cargo test --manifest-path src-tauri/Cargo.toml`
- Release packaging: `npm run tauri -- build`

Document any skipped validation with the exact blocker.

## Current Larger Maintenance Gaps

- Product direction is not selected.
- Automation remains disabled by design.
- Command-level Rust coverage is partial; attach and analyze command flow has
  initial tests, while create/list/download command paths still need coverage.
- Frontend UI/API flow tests are missing.
- Large media handling still sends full file byte arrays over Tauri IPC.
- Class diagram exports need regeneration or replacement.
