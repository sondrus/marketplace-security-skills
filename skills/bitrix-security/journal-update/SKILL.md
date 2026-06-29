---
name: journal-update
description: Use when updating and validating cumulative security-journal.json files for Bitrix module security runs from reviewed scan JSON outputs.
---

# Bitrix Vulnerability Journal Update

Use this skill after `scan` and `journal-review`.

It maintains the cumulative `security-journal.json` submitted by a Bitrix module developer. The key lifecycle logic is deterministic and lives in `scripts/update_journal.py`; do not hand-edit journal state unless the script cannot represent the case.

## Inputs

- reviewed scan JSON: output of `journal-review`
- optional previous `security-journal.json`
- optional module path, used to classify vanished findings as `removed` when the original file no longer exists
- optional final archive SHA-256

## Required Workflow

1. Run the updater:

```bash
python3 <skill-dir>/scripts/update_journal.py reviewed-scan.json \
  --previous security-journal.json \
  --module-path modules/vendor.module \
  --archive-sha256 <sha256> \
  --output security-journal.json
```

For the first run, omit `--previous`.

2. Validate the output before trusting it:

```bash
python3 <skill-dir>/scripts/update_journal.py --validate-only security-journal.json
```

3. Read `current_state` and report only the release-readiness summary:
   - `ready_for_submission` if blocking/open findings are zero
   - `blocked` if high/critical open findings remain
   - `needs_review` if accepted-risk or false-positive dispositions remain

## Deterministic Rules

- Findings are matched by a stable fingerprint derived from type, normalized file, line, and normalized description. Severity is intentionally excluded so a severity re-triage maps to the same finding instead of forking the journal.
- A current scan finding matching a previous finding keeps the same `journal_finding_id`.
- A current scan finding with no match creates a new journal finding.
- A previously open finding absent from the current scan is resolved:
  - `removed` if the last known file does not exist under `--module-path`
  - `fixed` otherwise
- A resolved finding that appears again is reopened with status `open`.
- Partner dispositions are preserved if present on a scan finding as `partner_disposition.status` with value `false_positive` or `accepted_risk`.
- If a current scan finding matches a previous finding that already has `false_positive` or `accepted_risk`, and the new scan does not explicitly provide a new `partner_disposition`, the previous developer disposition is kept. This prevents partners from re-marking the same finding after every rescan.
- The script never deletes historical findings or runs.

## Output

The updater writes one cumulative journal:

```json
{
  "schema_version": "1.0",
  "module": {},
  "current_state": {},
  "runs": [],
  "findings": []
}
```

The journal is the only artifact partners should submit with the final archive. Raw and reviewed scans may be kept locally for debugging but are not required for Marketplace submission unless requested.
