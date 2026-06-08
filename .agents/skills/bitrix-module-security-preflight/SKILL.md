---
name: bitrix-module-security-preflight
description: Orchestrates partner-side Bitrix module security preflight: scan, BUS-aware review, cumulative journal update, and final release-readiness summary.
---

# Bitrix Module Security Preflight

Use this skill when a Bitrix module developer needs the full partner-side pre-submission process, not just a raw scan.

This skill is an orchestrator. It does not contain security-audit heuristics. Keep audit improvements in `bitrix-module-security-scan`; keep BUS severity policy in `bitrix-vulnerability-journal-review`; keep lifecycle state in `bitrix-vulnerability-journal-update`.

## Inputs

- module path, for example `modules/vendor.module`
- optional previous `security-journal.json`
- optional final archive SHA-256

## Required Workflow

1. If a previous `security-journal.json` exists, prepare it as context for the scan. The scan skill may use it as `last-result.json`, but it must still verify findings against real code.
2. Run `bitrix-module-security-scan <module_path>`.
   - Expected output: `reports/<module_code>.json`
3. Run `bitrix-vulnerability-journal-review` on that scan output.
   - Recommended output: `reports/<module_code>.reviewed.json`
4. Run `bitrix-vulnerability-journal-update`:

```bash
python3 /Users/sv/.agents/skills/bitrix-vulnerability-journal-update/scripts/update_journal.py \
  reports/<module_code>.reviewed.json \
  --previous security-journal.json \
  --module-path <module_path> \
  --archive-sha256 <sha256> \
  --output security-journal.json
```

For the first run, omit `--previous`.

5. Validate the journal:

```bash
python3 /Users/sv/.agents/skills/bitrix-vulnerability-journal-update/scripts/update_journal.py \
  --validate-only security-journal.json
```

6. Report the final status from `current_state`:
   - `ready_for_submission`: no open findings and no unresolved dispositions
   - `blocked`: open high/critical findings remain
   - `needs_review`: open lower-severity findings or partner dispositions remain

## Output Artifacts

- `reports/<module_code>.json` — raw scan output
- `reports/<module_code>.reviewed.json` — BUS-aware reviewed scan
- `security-journal.json` — cumulative submission artifact

Only `security-journal.json` is the stable partner submission artifact. The raw and reviewed scan files are intermediate evidence and may be requested for debugging.

## Boundaries

- Do not modify `bitrix-module-security-scan` behavior from this skill.
- Do not manually edit reviewed severity; use `bitrix-vulnerability-journal-review`.
- Do not manually update lifecycle counters; use `bitrix-vulnerability-journal-update`.
- If the updater cannot classify a lifecycle transition, stop and explain the exact ambiguous case instead of inventing journal state.
