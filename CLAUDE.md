# CLAUDE.md

Claude Code entry point for `stegascope`.

This file is optimized for Claude Code. It preserves the same instruction routing as `AGENTS.md`; do not treat it as a separate policy layer.

## Claude Role
- Use Claude Code for code review, inspection, risk analysis, and validation planning.
- Do not treat Claude Code as the default implementation agent unless the user explicitly asks for implementation.
- Record review and inspection findings in `docs/management/REVIEW_FINDINGS.json` so Codex can read them.

## Codex Handoff
- Codex must read `docs/management/REVIEW_FINDINGS.json` before automation implementation work.
- Codex implementation work must resolve active Claude Code findings first, ordered by severity, unless the user explicitly overrides that priority.
- When a finding is resolved, update its status and keep the evidence or validation note in the findings file.

## Project
- id: `stegascope`
- root: `.`

## Required Context
Use these files as the authoritative project context. Start with `managementIndex`, then open `reviewFindings`, then open the specific files needed for the task. Paths are relative to this file.

| Key | Path |
| --- | --- |
| Management Index | `docs/management/INDEX.json` |
| Project | `docs/management/PROJECT.json` |
| Architecture | `docs/management/ARCHITECTURE.json` |
| Plan | `docs/management/PLAN.json` |
| Validation | `docs/management/VALIDATION.json` |
| Policy | `docs/management/POLICY.json` |
| Automation | `docs/management/AUTOMATION.json` |
| Review Findings | `docs/management/REVIEW_FINDINGS.json` |

## Optional Context
Open these files when they exist and are relevant to the current task.

| Key | Path |
| --- | --- |
| Legacy Instructions | `docs/management/LEGACY_INSTRUCTIONS.json` |
| Techniques | `docs/management/TECHNIQUES.json` |

## Compatibility
| Key | Value |
| --- | --- |
| Codex Prompt Directory | `.codex/` |
| Legacy Instruction Archive | `docs/management/LEGACY_INSTRUCTIONS.json` |

## Maintenance
- Keep `AGENTS.md` as the machine-readable source map.
- Keep this file semantically aligned with `AGENTS.md` when instruction routing changes.
- Do not duplicate large management documents here; link to the mapped files above.
