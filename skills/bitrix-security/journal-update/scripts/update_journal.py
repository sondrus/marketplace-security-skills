#!/usr/bin/env python3
"""Update and validate cumulative Bitrix vulnerability security journals."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
OPEN_STATUSES = {"open"}
DISPOSITION_STATUSES = {"false_positive", "accepted_risk"}
RESOLVED_STATUSES = {"fixed", "removed"}
ALLOWED_STATUSES = OPEN_STATUSES | DISPOSITION_STATUSES | RESOLVED_STATUSES
BLOCKING_SEVERITIES = {"critical", "high"}
REQUIRED_SCAN_VULN_KEYS = {
    "file",
    "line",
    "type",
    "severity",
    "description",
    "recommendation",
    "fix",
}
REQUIRED_JOURNAL_KEYS = {
    "schema_version",
    "module",
    "current_state",
    "runs",
    "findings",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON: {path}: {exc}") from exc


def write_json(path: Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def normalize_file(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    text = re.sub(r"^\./+", "", text)
    return text


def vulnerability_fingerprint(vuln: dict[str, Any]) -> str:
    # Severity is deliberately excluded: a re-triage that changes only the
    # severity must map to the SAME finding so the cumulative journal (status
    # history, partner_disposition) survives instead of forking into a new
    # open finding while the old one is marked fixed.
    parts = [
        normalize_text(vuln.get("type")),
        normalize_file(vuln.get("file")),
        normalize_text(vuln.get("line")),
        normalize_text(vuln.get("description")),
    ]
    material = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


def validate_scan(doc: dict[str, Any]) -> None:
    if not isinstance(doc, dict):
        raise SystemExit("Scan root must be an object")
    if "success" not in doc:
        raise SystemExit("Scan missing top-level success")
    data = doc.get("data")
    if not isinstance(data, dict):
        raise SystemExit("Scan data must be an object")
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise SystemExit("Scan data.vulnerabilities must be an array")
    for idx, vuln in enumerate(vulns):
        if not isinstance(vuln, dict):
            raise SystemExit(f"Scan vulnerability #{idx} must be an object")
        missing = sorted(REQUIRED_SCAN_VULN_KEYS - set(vuln))
        if missing:
            raise SystemExit(f"Scan vulnerability #{idx} missing keys: {', '.join(missing)}")


def validate_journal(doc: dict[str, Any]) -> None:
    if not isinstance(doc, dict):
        raise SystemExit("Journal root must be an object")
    missing = sorted(REQUIRED_JOURNAL_KEYS - set(doc))
    if missing:
        raise SystemExit(f"Journal missing keys: {', '.join(missing)}")
    if doc["schema_version"] != SCHEMA_VERSION:
        raise SystemExit(f"Unsupported schema_version: {doc['schema_version']!r}")
    if not isinstance(doc["module"], dict):
        raise SystemExit("Journal module must be an object")
    if not isinstance(doc["current_state"], dict):
        raise SystemExit("Journal current_state must be an object")
    if not isinstance(doc["runs"], list):
        raise SystemExit("Journal runs must be an array")
    if not isinstance(doc["findings"], list):
        raise SystemExit("Journal findings must be an array")

    ids: set[str] = set()
    fingerprints: set[str] = set()
    for idx, finding in enumerate(doc["findings"]):
        if not isinstance(finding, dict):
            raise SystemExit(f"Journal finding #{idx} must be an object")
        for key in ("journal_finding_id", "fingerprint", "type", "severity", "status", "events"):
            if key not in finding:
                raise SystemExit(f"Journal finding #{idx} missing key: {key}")
        if finding["status"] not in ALLOWED_STATUSES:
            raise SystemExit(f"Journal finding #{idx} has invalid status: {finding['status']!r}")
        if finding["journal_finding_id"] in ids:
            raise SystemExit(f"Duplicate journal_finding_id: {finding['journal_finding_id']}")
        ids.add(finding["journal_finding_id"])
        fingerprints.add(str(finding["fingerprint"]))
        if not isinstance(finding["events"], list) or not finding["events"]:
            raise SystemExit(f"Journal finding #{idx} must have non-empty events")

    state = doc["current_state"]
    expected_open = sum(1 for f in doc["findings"] if f["status"] == "open")
    expected_blocking = sum(
        1
        for f in doc["findings"]
        if f["status"] == "open" and str(f.get("severity", "")).lower() in BLOCKING_SEVERITIES
    )
    if state.get("open_findings") != expected_open:
        raise SystemExit("current_state.open_findings is inconsistent")
    if state.get("blocking_findings_open") != expected_blocking:
        raise SystemExit("current_state.blocking_findings_open is inconsistent")


def module_code_from_scan(scan: dict[str, Any], fallback: str | None) -> str:
    request_id = str(scan.get("requestId") or "")
    if request_id and "-" in request_id:
        return request_id.rsplit("-", 1)[0]
    if fallback:
        return Path(fallback).name
    return "unknown-module"


def initial_journal(scan: dict[str, Any], module_path: str | None, archive_sha256: str | None) -> dict[str, Any]:
    module_code = module_code_from_scan(scan, module_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "module": {
            "code": module_code,
        },
        "current_state": {
            "status": "ready_for_submission",
            "last_run_id": None,
            "archive_sha256": archive_sha256,
            "open_findings": 0,
            "blocking_findings_open": 0,
            "false_positive_findings": 0,
            "accepted_risk_findings": 0,
            "fixed_findings": 0,
            "removed_findings": 0,
            "total_findings": 0,
        },
        "runs": [],
        "findings": [],
    }


def next_finding_id(existing: list[dict[str, Any]]) -> str:
    max_num = 0
    for finding in existing:
        match = re.fullmatch(r"JF-(\d+)", str(finding.get("journal_finding_id", "")))
        if match:
            max_num = max(max_num, int(match.group(1)))
    return f"JF-{max_num + 1:05d}"


def scan_location(vuln: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": normalize_file(vuln.get("file")),
        "line": str(vuln.get("line", "")),
    }


def disposition_status(vuln: dict[str, Any]) -> str:
    disposition = vuln.get("partner_disposition")
    if isinstance(disposition, dict):
        status = str(disposition.get("status", "")).lower()
        if status in DISPOSITION_STATUSES:
            return status
    return "open"


def disposition_node(vuln: dict[str, Any]) -> dict[str, Any] | None:
    disposition = vuln.get("partner_disposition")
    if not isinstance(disposition, dict):
        return None
    status = str(disposition.get("status", "")).lower()
    if status not in DISPOSITION_STATUSES:
        return None
    return disposition


def preserved_disposition(finding: dict[str, Any]) -> dict[str, Any] | None:
    latest = finding.get("latest_vulnerability")
    if isinstance(latest, dict):
        disposition = disposition_node(latest)
        if disposition:
            return disposition
    status = str(finding.get("status", "")).lower()
    if status in DISPOSITION_STATUSES:
        return {"status": status}
    return None


def file_exists(module_path: str | None, file_path: str | None) -> bool | None:
    if not module_path or not file_path:
        return None
    return (Path(module_path) / file_path).exists()


def append_event(finding: dict[str, Any], run_id: str, event: str, extra: dict[str, Any] | None = None) -> None:
    node: dict[str, Any] = {
        "run_id": run_id,
        "event": event,
        "at": now_iso(),
    }
    if extra:
        node.update(extra)
    finding.setdefault("events", []).append(node)


def update_current_state(journal: dict[str, Any], archive_sha256: str | None, run_id: str) -> None:
    findings = journal["findings"]
    counts = Counter(str(f["status"]) for f in findings)
    blocking_open = sum(
        1
        for f in findings
        if f["status"] == "open" and str(f.get("severity", "")).lower() in BLOCKING_SEVERITIES
    )
    status = "ready_for_submission"
    if blocking_open:
        status = "blocked"
    elif counts["open"] or counts["false_positive"] or counts["accepted_risk"]:
        status = "needs_review"

    journal["current_state"] = {
        "status": status,
        "last_run_id": run_id,
        "archive_sha256": archive_sha256,
        "open_findings": counts["open"],
        "blocking_findings_open": blocking_open,
        "false_positive_findings": counts["false_positive"],
        "accepted_risk_findings": counts["accepted_risk"],
        "fixed_findings": counts["fixed"],
        "removed_findings": counts["removed"],
        "total_findings": len(findings),
    }


def severity_counts(vulns: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(vuln.get("severity", "")).lower() for vuln in vulns)
    return {severity: counts[severity] for severity in ("critical", "high", "medium", "low", "info") if counts[severity]}


def update_journal(
    scan: dict[str, Any],
    previous: dict[str, Any] | None,
    module_path: str | None,
    archive_sha256: str | None,
) -> dict[str, Any]:
    validate_scan(scan)
    journal = deepcopy(previous) if previous else initial_journal(scan, module_path, archive_sha256)
    if previous:
        validate_journal(journal)
    if archive_sha256 is None:
        archive_sha256 = journal.get("current_state", {}).get("archive_sha256")

    run_id = str(scan.get("requestId") or f"{module_code_from_scan(scan, module_path)}-{len(journal['runs']) + 1}")
    current_vulns = scan["data"]["vulnerabilities"]
    current_by_fingerprint = {vulnerability_fingerprint(v): v for v in current_vulns}
    existing_by_fingerprint = {str(f["fingerprint"]): f for f in journal["findings"]}

    new_count = 0
    reopened_count = 0
    still_open_count = 0

    for fingerprint, vuln in current_by_fingerprint.items():
        location = scan_location(vuln)
        finding = existing_by_fingerprint.get(fingerprint)
        if finding:
            vuln = deepcopy(vuln)
            was_resolved = finding["status"] in RESOLVED_STATUSES
            disposition = disposition_node(vuln)
            if disposition is None and finding["status"] in DISPOSITION_STATUSES:
                disposition = preserved_disposition(finding)
                if disposition:
                    vuln["partner_disposition"] = deepcopy(disposition)
            status = disposition_status(vuln)
            finding["status"] = status
            finding["severity"] = str(vuln.get("severity", "")).lower()
            finding["type"] = str(vuln.get("type", ""))
            finding["last_seen_run_id"] = run_id
            finding["current_location"] = location
            finding["latest_vulnerability"] = vuln
            append_event(
                finding,
                run_id,
                "reopened" if was_resolved else "detected_again",
                {"location": location, "status": status},
            )
            if was_resolved:
                reopened_count += 1
            else:
                still_open_count += 1
            continue

        status = disposition_status(vuln)
        finding_id = next_finding_id(journal["findings"])
        new_finding = {
            "journal_finding_id": finding_id,
            "fingerprint": fingerprint,
            "type": str(vuln.get("type", "")),
            "severity": str(vuln.get("severity", "")).lower(),
            "status": status,
            "first_seen_run_id": run_id,
            "last_seen_run_id": run_id,
            "resolved_run_id": None,
            "original_location": location,
            "current_location": location,
            "latest_vulnerability": deepcopy(vuln),
            "events": [],
        }
        append_event(new_finding, run_id, "detected", {"location": location, "status": status})
        journal["findings"].append(new_finding)
        existing_by_fingerprint[fingerprint] = new_finding
        new_count += 1

    resolved_count = 0
    for finding in journal["findings"]:
        if finding["fingerprint"] in current_by_fingerprint:
            continue
        if finding["status"] not in OPEN_STATUSES:
            continue
        last_location = finding.get("current_location") or finding.get("original_location") or {}
        last_file = normalize_file(last_location.get("file"))
        exists = file_exists(module_path, last_file)
        new_status = "removed" if exists is False else "fixed"
        finding["status"] = new_status
        finding["resolved_run_id"] = run_id
        finding["current_location"] = None
        finding["resolution"] = {
            "type": "file_removed" if new_status == "removed" else "not_reproduced_after_rescan",
            "resolved_in_run": run_id,
            "reason": (
                "Last known vulnerable file is absent in the current module tree."
                if new_status == "removed"
                else "The reviewed scan no longer reports a matching finding for the current archive."
            ),
        }
        append_event(finding, run_id, "resolved", {"status": new_status})
        resolved_count += 1

    run = {
        "run_id": run_id,
        "created_at": now_iso(),
        "archive_sha256": archive_sha256,
        "scanner_request_id": scan.get("requestId"),
        "input_summary": scan.get("data", {}).get("summary"),
        "summary": {
            "current_scan_findings": len(current_vulns),
            "severity_counts": severity_counts(current_vulns),
            "new_findings": new_count,
            "still_open_findings": still_open_count,
            "reopened_findings": reopened_count,
            "resolved_since_previous_run": resolved_count,
        },
    }
    journal["runs"].append(run)
    update_current_state(journal, archive_sha256, run_id)
    validate_journal(journal)
    return journal


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Update Bitrix cumulative security journal")
    parser.add_argument("scan", nargs="?", type=Path, help="Reviewed scan JSON")
    parser.add_argument("--previous", type=Path, help="Previous security-journal.json")
    parser.add_argument("--module-path", help="Module path for file-existence resolution")
    parser.add_argument("--archive-sha256", help="SHA-256 of final submitted archive")
    parser.add_argument("--output", type=Path, help="Output security-journal.json")
    parser.add_argument("--validate-only", action="store_true", help="Validate journal and exit")
    args = parser.parse_args(argv)

    if args.validate_only:
        if not args.scan:
            raise SystemExit("--validate-only requires a journal path")
        validate_journal(load_json(args.scan))
        print("VALID security journal")
        return 0

    if not args.scan:
        raise SystemExit("scan argument is required unless --validate-only is used")
    if not args.output:
        raise SystemExit("--output is required")

    scan = load_json(args.scan)
    previous = load_json(args.previous) if args.previous else None
    updated = update_journal(scan, previous, args.module_path, args.archive_sha256)
    write_json(args.output, updated)
    print(json.dumps(updated["current_state"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
