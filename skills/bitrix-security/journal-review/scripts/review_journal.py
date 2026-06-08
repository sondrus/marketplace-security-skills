#!/usr/bin/env python3
"""Review and validate Bitrix vulnerability journals.

The script preserves each vulnerability record, replaces only severity with the
BUS-aware reviewed severity, and adds a reviewed object with rationale.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from copy import deepcopy
from datetime import date
from pathlib import Path
from typing import Any

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}
REQUIRED_VULN_KEYS = {
    "file",
    "line",
    "type",
    "severity",
    "description",
    "recommendation",
    "fix",
}
REQUIRED_REVIEWED_KEYS = {
    "oldSeverity",
    "newSeverity",
    "changed",
    "category",
    "versionScope",
    "version",
    "currentVersionRelevance",
    "action",
    "confidence",
    "rationale",
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON: {path}: {exc}") from exc


def validate_input(doc: dict[str, Any]) -> None:
    if not isinstance(doc, dict):
        raise SystemExit("Journal root must be a JSON object")
    if "success" not in doc:
        raise SystemExit("Journal missing top-level key: success")
    data = doc.get("data")
    if not isinstance(data, dict):
        raise SystemExit("Journal key data must be an object")
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise SystemExit("Journal key data.vulnerabilities must be an array")
    for idx, vuln in enumerate(vulns):
        if not isinstance(vuln, dict):
            raise SystemExit(f"Vulnerability #{idx} must be an object")
        missing = sorted(REQUIRED_VULN_KEYS - set(vuln))
        if missing:
            raise SystemExit(f"Vulnerability #{idx} missing keys: {', '.join(missing)}")
        if str(vuln["severity"]).lower() not in ALLOWED_SEVERITIES:
            raise SystemExit(f"Vulnerability #{idx} has invalid severity: {vuln['severity']!r}")


def validate_reviewed_output(original: dict[str, Any], reviewed: dict[str, Any]) -> None:
    validate_input(reviewed)
    orig_vulns = original["data"]["vulnerabilities"]
    rev_vulns = reviewed["data"]["vulnerabilities"]
    if len(orig_vulns) != len(rev_vulns):
        raise SystemExit("Reviewed journal changed vulnerability count")

    for idx, (orig, rev) in enumerate(zip(orig_vulns, rev_vulns, strict=True)):
        if "reviewed" not in rev:
            raise SystemExit(f"Reviewed vulnerability #{idx} missing reviewed node")
        reviewed_node = rev["reviewed"]
        if not isinstance(reviewed_node, dict):
            raise SystemExit(f"Reviewed node #{idx} must be an object")
        missing = sorted(REQUIRED_REVIEWED_KEYS - set(reviewed_node))
        if missing:
            raise SystemExit(f"Reviewed node #{idx} missing keys: {', '.join(missing)}")
        if reviewed_node["oldSeverity"] != orig["severity"]:
            raise SystemExit(f"Reviewed node #{idx} oldSeverity does not match source severity")
        if reviewed_node["newSeverity"] != rev["severity"]:
            raise SystemExit(f"Reviewed node #{idx} newSeverity does not match output severity")
        if reviewed_node["changed"] != (reviewed_node["oldSeverity"] != reviewed_node["newSeverity"]):
            raise SystemExit(f"Reviewed node #{idx} changed flag is inconsistent")

        orig_with_new_severity = deepcopy(orig)
        orig_with_new_severity["severity"] = rev["severity"]
        rev_without_reviewed = deepcopy(rev)
        del rev_without_reviewed["reviewed"]
        if orig_with_new_severity != rev_without_reviewed:
            raise SystemExit(
                f"Reviewed vulnerability #{idx} changed fields other than severity/reviewed"
            )

    summary = reviewed.get("data", {}).get("reviewSummary")
    if not isinstance(summary, dict):
        raise SystemExit("Reviewed journal missing data.reviewSummary object")


def version_of(file_path: str) -> str:
    parts = str(file_path).replace("\\", "/").split("/")
    for part in parts:
        if part == ".last_version" or re.fullmatch(r"\d+\.\d+\.\d+", part):
            return part
    return "current"


def scope_of(version: str) -> str:
    return "historical-update" if re.fullmatch(r"\d+\.\d+\.\d+", version) else "current"


def relative_path(file_path: str) -> str:
    return re.sub(r"^.*(?:\.last_version|\d+\.\d+\.\d+)/", "", str(file_path).replace("\\", "/"))


def has_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def review_vulnerability(vuln: dict[str, Any]) -> dict[str, Any]:
    old_severity = str(vuln["severity"]).lower()
    version = version_of(str(vuln["file"]))
    scope = scope_of(version)
    rel = relative_path(str(vuln["file"]))
    description = str(vuln.get("description", ""))
    text = "\n".join(
        str(vuln.get(key, ""))
        for key in ("type", "description", "file", "line")
    )

    new_severity = old_severity
    category = "kept-as-reported"
    rationale = (
        "Severity left unchanged after review; no stronger Bitrix/BUS-specific "
        "downgrade condition was identified from the journal text alone."
    )
    action = "fix"
    confidence = "medium"
    relevance = "present-in-current-scan" if scope == "current" else "historical-update-package"

    vuln_type = str(vuln["type"])
    is_hardcoded_secret = vuln_type == "Hardcoded Secret"
    is_token = (
        not is_hardcoded_secret
        and re.search(r"ACCESS_TOKEN|API-Key|OAuth|authorization token|bearer", text, re.I)
    )
    is_public_reflected = has_any(
        text,
        [
            r"без авторизац",
            r"Неаутентифицирован",
            r"пользовательск(?:ий|ого) (?:ввод|поисковый запрос)",
            r"query string",
            r"параметр запроса",
            r"из запроса",
            r"\$request",
            r'\$arResult\["REQUEST"\]',
            r"SKU_DETAIL_ID",
            r"containerId",
            r"FROM/TO",
            r"ORIGINAL_QUERY",
            r"sf_EMAIL",
            r"CONFIRM_CODE",
        ],
    )
    is_admin_stored = has_any(
        text,
        [
            r"с правами",
            r"правом редакт",
            r"редактор",
            r"контент-менеджер",
            r"инфоблок",
            r"товар",
            r"раздел",
            r"баннер",
            r"новост",
            r"сотрудник",
            r"служб(?:а|ами) доставки",
            r"локац",
            r"HL-справочник",
            r"рубри",
            r"карточк",
            r"свойств",
            r"из БД",
            r"Stored XSS",
        ],
    )
    is_path_disclosure = re.search(
        r"__FILE__|абсолютн(?:ый|ого) путь|путь к (?:шаблону|файлу)|структур[ау] файловой системы",
        text,
        re.I,
    )
    is_open_redirect = vuln_type == "Open Redirect"
    is_backurl_redirect = is_open_redirect and re.search(r"backurl|авторизац", text, re.I)
    is_editable_redirect = is_open_redirect and re.search(
        r"правами на редакт|свойства лендинга|PROPERTY_REDIRECT",
        text,
        re.I,
    )
    is_comments_moderator_xss = vuln_type == "Cross-Site Scripting" and re.search(
        r"catalog\.comments|approve|unapprove|модератор",
        text,
        re.I,
    )
    is_idor_or_mass_assignment = re.search(
        r"\bIDOR\b|mass assignment|провер(?:к[аи]) владельц|без проверки владельц|owner",
        text,
        re.I,
    )
    has_privileged_or_money_sink = re.search(
        r"денеж|финансов|привилег|цена|ценой|количеств|скидк|купон|бонус|"
        r"Sale\\Order|OnSalePayment|OnSaleOrderSaved|order",
        text,
        re.I,
    )
    is_financial_logic = re.search(
        r"манипуляц.*(?:цен|количеств|скидк)|обход купон|начислени[ея] бонус|"
        r"изменени[ея].*(?:цен|скидк|купон|бонус)|Sale\\Order|OnSalePayment|OnSaleOrderSaved",
        text,
        re.I,
    )
    is_confirmed_backdoor = (
        re.search(r"eval\s*\(|gzuncompress|base64_decode|обфускац", text, re.I)
        and re.search(
            r"exec|shell_exec|system|passthru|proc_open|curl|fsockopen|file_put_contents|"
            r"fopen|unlink|эксфильтр|exfil|сетев|файлов",
            text,
            re.I,
        )
    )
    is_sql_injection = re.search(r"SQL[- ]?инъек|SQL Injection", vuln_type + "\n" + text, re.I)
    is_cross_priv_stored_xss = (
        vuln_type == "Cross-Site Scripting"
        and is_admin_stored
        and re.search(r"аноним|клиент|покупател|оператор|пользователь сайта|отзыв|форма", text, re.I)
        and re.search(r"админ|администратор|модерац|списк[и]? заказ|очеред", text, re.I)
    )
    is_account_takeover = re.search(
        r"войти в чуж|чужой .*аккаунт|account takeover",
        description,
        re.I,
    )

    if is_hardcoded_secret:
        new_severity = "low"
        category = "hardcoded-default-token-hygiene"
        rationale = (
            "Kept as low because impact depends on whether the default token is still "
            "valid and what external API permissions it has. Remove it, but it is "
            "weaker than public XSS/auth findings unless real secret scope is confirmed."
        )
        action = "remove-default-secret"
    elif is_confirmed_backdoor:
        new_severity = "high"
        category = "confirmed-backdoor"
        rationale = (
            "Kept/raised as high because the finding combines suspicious obfuscation "
            "with an execution, network, filesystem, or exfiltration sink. Obfuscation "
            "alone would not be sufficient."
        )
        action = "block-and-escalate-security-review"
        confidence = "medium"
    elif is_idor_or_mass_assignment and has_privileged_or_money_sink:
        new_severity = "high"
        category = "idor-or-mass-assignment-high-impact"
        rationale = (
            "Kept/raised as high because the finding describes IDOR/mass assignment "
            "without owner checks affecting privileged or monetary behavior and reachable "
            "by an anonymous or ordinary site user."
        )
        action = "add-owner-authorization-checks"
        confidence = "medium"
    elif is_financial_logic:
        new_severity = "high"
        category = "financial-business-logic"
        rationale = (
            "Kept/raised as high because the finding points to direct financial business "
            "logic impact such as price, quantity, discount, coupon, bonus, basket, order, "
            "or payment manipulation."
        )
        action = "fix-business-logic-authorization"
        confidence = "medium"
    elif is_sql_injection:
        new_severity = "medium"
        category = "sql-injection"
        rationale = "Kept as medium by default under the BUS Marketplace triage policy; raise only when exploit impact is proven beyond the journal text."
        action = "parameterize-query"
        confidence = "medium"
    elif vuln_type == "Cross-Site Scripting":
        if is_public_reflected and not is_admin_stored:
            new_severity = "medium"
            category = "public-reflected-xss"
            rationale = "Set to medium because reflected XSS is significant but not high under the BUS Marketplace triage policy unless chained to stronger impact proven outside the journal text."
            confidence = "high"
        elif is_cross_priv_stored_xss:
            new_severity = "medium"
            category = "cross-privilege-stored-xss"
            rationale = (
                "Set to medium because data controlled by a lower-privileged actor appears "
                "to execute in an administrator/moderation/order interface."
            )
        elif is_comments_moderator_xss and is_public_reflected:
            new_severity = "medium"
            category = "targeted-moderator-reflected-xss"
            rationale = "Set to medium because the issue targets a privileged moderation/comment flow but is not a direct high-impact IDOR, financial bug, or backdoor."
        elif is_admin_stored:
            new_severity = "low"
            category = "stored-xss-trusted-editor-content"
            rationale = (
                "Downgraded because the journal describes a stored XSS source controlled "
                "by a Bitrix admin/content editor or another trusted content-management "
                "role. In BUS such users can normally publish HTML/JS through legitimate "
                "site-management mechanisms, so this is template hardening rather than a "
                "high module vulnerability unless a low-privileged/external source is proven."
            )
            action = "harden-output-escaping"
            confidence = "high"
        else:
            new_severity = "medium" if old_severity == "high" else old_severity
            category = "xss-unclear-source"
            rationale = (
                "Adjusted conservatively because the journal does not clearly prove a "
                "low-privileged or public payload source. Confirm source permissions "
                "before treating as a blocker."
            )
            action = "validate-source-and-fix-escaping"
            confidence = "low"
    elif is_token:
        new_severity = "medium" if old_severity == "low" else old_severity
        category = "potential-api-token-exposure"
        rationale = (
            "Kept as a real issue if the value is an OAuth/API-Key/bearer-style secret "
            "or if transport/authentication handling can expose such secrets. If the "
            "field is only a public widget/model identifier, this finding should be "
            "removed or downgraded after code/value validation."
        )
        action = "validate-token-kind-and-keep-server-side"
    elif vuln_type == "Authentication Bypass":
        new_severity = "high" if is_account_takeover else "medium"
        category = "account-takeover" if is_account_takeover else "authenticated-or-limited-authorization-bypass"
        rationale = (
            "Kept as high because the finding describes possible account takeover or login into another user's account."
            if is_account_takeover
            else "Set to medium because the finding describes authorization bypass or privilege misuse, but not a direct high-impact IDOR, financial bug, or confirmed account takeover in the journal text."
        )
        if scope != "current":
            rationale += " It is also under a historical update package and must be reproduced on the latest installed version before being used as a current blocker."
        action = "verify-on-latest-version"
    elif vuln_type == "CSRF":
        new_severity = "medium"
        category = "csrf-state-change"
        rationale = (
            "Kept as medium because the finding describes state change without "
            "check_bitrix_sessid; raise only if cross-user deletion or higher-impact "
            "state change is confirmed."
            if scope == "current"
            else "Kept as medium for the affected historical version, but it is not shown "
            "in .last_version; verify on the latest installed version before using it as "
            "a current blocker."
        )
        action = "add-sessid-and-owner-checks"
    elif is_open_redirect:
        if is_backurl_redirect:
            new_severity = "medium"
            category = "public-open-redirect"
            rationale = (
                "Kept as medium because request-controlled backurl redirect can support "
                "phishing after login; restrict to relative/local URLs."
                if scope == "current"
                else "Kept as medium for the affected historical version, but it is not "
                "shown in .last_version; verify on latest before treating as current blocker."
            )
            action = "allowlist-local-redirects"
        elif is_editable_redirect:
            new_severity = "low"
            category = "trusted-editor-open-redirect"
            rationale = (
                "Downgraded because the redirect target appears controlled through an "
                "editable Bitrix content/landing property. This should be hardened with a "
                "URL allowlist, but it is not equivalent to a public request-controlled "
                "redirect unless low-privileged write access is proven."
            )
            action = "allowlist-local-redirects"
        else:
            new_severity = "medium"
            category = "open-redirect-unclear-source"
            rationale = (
                "Left as medium pending confirmation of whether the redirect target is "
                "request-controlled or only editable by trusted administrators."
            )
            action = "validate-source-and-allowlist"
            confidence = "low"
    elif is_path_disclosure:
        new_severity = "low"
        category = "path-disclosure-hygiene"
        rationale = (
            "Kept/downgraded to low because absolute path disclosure is useful "
            "reconnaissance but usually does not create direct compromise in BUS without "
            "another vulnerability."
        )
        action = "remove-debug-output"
        confidence = "high"

    if scope == "historical-update":
        rationale += (
            " Path is under a versioned update package; this affects current "
            "publication triage."
        )

    return {
        "oldSeverity": old_severity,
        "newSeverity": new_severity,
        "changed": old_severity != new_severity,
        "category": category,
        "versionScope": scope,
        "version": version,
        "currentVersionRelevance": relevance,
        "action": action,
        "confidence": confidence,
        "rationale": rationale,
    }


def counts_by(items: list[Any], key_fn: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        key = str(key_fn(item))
        counts[key] = counts.get(key, 0) + 1
    return counts


def review_journal(doc: dict[str, Any]) -> dict[str, Any]:
    validate_input(doc)
    out = deepcopy(doc)
    out["data"]["vulnerabilities"] = []
    for vuln in doc["data"]["vulnerabilities"]:
        reviewed = review_vulnerability(vuln)
        new_vuln = deepcopy(vuln)
        new_vuln["severity"] = reviewed["newSeverity"]
        new_vuln["reviewed"] = reviewed
        out["data"]["vulnerabilities"].append(new_vuln)

    vulns = out["data"]["vulnerabilities"]
    source_vulns = doc["data"]["vulnerabilities"]
    current = [v for v in vulns if v["reviewed"]["versionScope"] == "current"]
    historical = [v for v in vulns if v["reviewed"]["versionScope"] == "historical-update"]
    source_current = [v for v in source_vulns if scope_of(version_of(str(v["file"]))) == "current"]
    source_historical = [
        v for v in source_vulns if scope_of(version_of(str(v["file"]))) == "historical-update"
    ]
    caveats = [
        "Type, file, line, description, recommendation and fix are preserved from the source journal.",
        "Severity is replaced with reviewed triage severity.",
    ]
    if any(v["reviewed"]["category"] == "potential-api-token-exposure" for v in vulns):
        caveats.append(
            "Token exposure remains conditional: validate whether the value is an OAuth/API-Key/bearer token or only a public widget/model identifier."
        )
    if historical:
        caveats.append(
            "Historical update package findings are not current-version blockers unless reproduced on the latest installed version."
        )

    out["data"]["reviewSummary"] = {
        "reviewedAt": date.today().isoformat(),
        "method": (
            "BUS-aware triage: preserve original finding fields except severity, "
            "add reviewed node with old severity and rationale."
        ),
        "totals": {
            "vulnerabilities": len(vulns),
            "changedSeverity": sum(1 for v in vulns if v["reviewed"]["changed"]),
            "unchangedSeverity": sum(1 for v in vulns if not v["reviewed"]["changed"]),
        },
        "rawSeverityCounts": counts_by(source_vulns, lambda v: v["severity"]),
        "reviewedSeverityCounts": counts_by(vulns, lambda v: v["severity"]),
        "currentScope": {
            "total": len(current),
            "rawSeverityCounts": counts_by(source_current, lambda v: v["severity"]),
            "reviewedSeverityCounts": counts_by(current, lambda v: v["severity"]),
            "reviewedCategories": counts_by(current, lambda v: v["reviewed"]["category"]),
        },
        "historicalUpdatePackages": {
            "total": len(historical),
            "rawSeverityCounts": counts_by(source_historical, lambda v: v["severity"]),
            "reviewedSeverityCounts": counts_by(historical, lambda v: v["severity"]),
            "reviewedCategories": counts_by(historical, lambda v: v["reviewed"]["category"]),
        },
        "caveats": caveats,
    }
    validate_reviewed_output(doc, out)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Review and validate Bitrix vulnerability journals")
    parser.add_argument("input", type=Path, help="Input JSON journal")
    parser.add_argument("--output", type=Path, help="Output reviewed JSON journal")
    parser.add_argument("--validate-only", action="store_true", help="Validate an existing reviewed journal")
    args = parser.parse_args()

    doc = load_json(args.input)
    if args.validate_only:
        validate_input(doc)
        original_like = deepcopy(doc)
        for vuln in original_like["data"]["vulnerabilities"]:
            reviewed = vuln.get("reviewed")
            if not isinstance(reviewed, dict):
                raise SystemExit("validate-only requires reviewed nodes on every vulnerability")
            vuln["severity"] = reviewed["oldSeverity"]
            del vuln["reviewed"]
        validate_reviewed_output(original_like, doc)
        print("VALID reviewed journal")
        return 0

    if not args.output:
        raise SystemExit("--output is required unless --validate-only is used")
    reviewed = review_journal(doc)
    args.output.write_text(json.dumps(reviewed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(reviewed["data"]["reviewSummary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
