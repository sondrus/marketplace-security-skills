#!/usr/bin/env python3
"""Deterministic recon sweep for the Bitrix `scan` skill.

ONE pass over the module replaces the ~20-command grep recon table plus the
5-command safety pass — every pattern is applied while each file is read once,
so the agent spends a single tool round-trip instead of dozens. The model is a
slow reasoning model behind a relay; cutting serial round-trips is the dominant
latency lever, so this script exists purely to collapse them.

Correctness notes:
  * Cyrillic-safe. Many Bitrix modules are windows-1251. We read raw bytes and
    decode utf-8 → cp1251 → latin-1 (latin-1 never fails), so signals in 1251
    files are NOT silently dropped — this is the Python equivalent of `grep -a`
    on those files, which the SKILL.md flags as a critical blind spot.
  * Vendored/binary files are skipped (vendor, composer, node_modules, .git,
    .idea, *.min.js/css, known binary suffixes) — same exclusions as the
    skill's Step 1.1 find.
  * Output is `relpath:line: <trimmed match>` grouped by category, plus a target
    file count for `scannedFiles`. Per-category matches are capped (loud note on
    truncation) so a huge module cannot blow up the context.

This does NOT replace Phase 2 (reading entry-point files in full) — it only
produces the signal map that Phase 2 prioritises.
"""

import os
import re
import sys

IGNORED_DIRS = {".git", ".svn", ".idea", ".vscode", "node_modules", "vendor", "composer", "__pycache__"}
TEXT_SUFFIXES = {
    ".php", ".php5", ".php7", ".phtml", ".inc", ".tpl", ".html", ".htm",
    ".js", ".json", ".xml", ".txt", ".ini", ".conf", ".sql", ".css", ".phps",
}
BINARY_SUFFIXES = {
    ".pyc", ".so", ".dll", ".exe", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mo", ".bin", ".jar", ".class",
}
MAX_FILE_BYTES = 2_000_000
MAX_MATCHES_PER_CATEGORY = 200

# (category, compiled regex). Patterns mirror scan/SKILL.md Step 1.2 recon table
# AND the cheap "страховочный проход" dangerous patterns (eval/exec/unserialize/
# direct request echo/preg /e) — folded in here so the standalone safety pass is
# no longer a separate set of round-trips. Case-sensitive to match the original
# `grep -E` behaviour.
_PATTERNS = [
    ("Bitrix Controllers", r"\\Bitrix\\Main\\Engine\\Controller|configureActions|'prefilters'\s*=>\s*\[\s*\]|-prefilters"),
    ("AJAX endpoints", r"\$_REQUEST\['action'\]|ajax\.php|vote_ajax|create_vote_ajax"),
    ("Source: HTTP superglobals", r"\$_GET\b|\$_POST\b|\$_REQUEST\b|\$_FILES\b|\$_SERVER\b|\$_COOKIE\b"),
    ("Source: Bitrix request", r"getRequest\(\)|HttpRequest|Context::getCurrent"),
    ("Sink: code exec", r"\beval\s*\(|\bassert\s*\(|create_function\s*\(|preg_replace\s*\([^)]*/[a-zA-Z]*e[a-zA-Z]*['\"]"),
    ("Regex injection (var pattern)", r"preg_(match|replace|match_all|split)\s*\(\s*[^,]*\$"),
    ("Sink: OS command", r"\b(exec|shell_exec|system|passthru|proc_open|popen)\s*\(|escapeshellcmd"),
    ("Weak crypto compare", r"(md5|sha1|hash_hmac|crc32)\s*\([^)]*\)\s*(==|!=)"),
    ("Insecure TLS", r"CURLOPT_SSL_VERIFYPEER|CURLOPT_SSL_VERIFYHOST|verify\s*=>\s*false"),
    ("Sink: deserialize", r"\bunserialize\s*\("),
    ("Sink: include/require var", r"\b(include|require)(_once)?\s*[\(\s]*\$"),
    ("Sink: SQL", r"CDatabase::Query|->Query\s*\(\s*\"[^\"]*\$|Application::getConnection|getConnection\(\)->query\s*\("),
    ("Sink: HTML echo of request", r"<\?=\s*\$_(GET|POST|REQUEST)|echo\s+\$_(GET|POST|REQUEST)"),
    ("Sink: file ops on var", r"file_get_contents\s*\(\s*\$|file_put_contents\s*\(\s*\$|fopen\s*\(\s*\$|unlink\s*\(\s*\$|IncludeFile\s*\(\s*\$"),
    ("Sink: SSRF", r"CHTTP|HttpClient|curl_setopt|curl_exec"),
    ("Sink: file upload", r"move_uploaded_file"),
    ("Escaping (context)", r"htmlspecialcharsbx|htmlspecialchars\s*\("),
    ("Sink: SSTI", r"new\s+\\?Twig|Twig\\Environment|createTemplate\s*\(|Smarty|->fetch\s*\(\s*\$|->display\s*\(\s*\$"),
    ("Sink: XXE", r"simplexml_load_(string|file)|DOMDocument|->loadXML|XMLReader|xml_parse|libxml_disable_entity_loader|LIBXML_DTDLOAD|LIBXML_NOENT"),
    ("Sink: Open Redirect", r"LocalRedirect\s*\(\s*\$|LocalRedirect\s*\([^)]*\$_(GET|POST|REQUEST)|header\s*\(\s*['\"]Location:|->redirect\s*\(\s*\$"),
    ("Sink: Header Injection", r"\bmail\s*\(|->setHeader|AddHeader"),
    ("Hardcoded secrets", r"(api[_-]?key|token|secret|password|Bearer)\s*[=:]\s*['\"][A-Za-z0-9_\-.]{16,}"),
    ("Auth checks", r"IsAuthorized|GetGroupRight|check_bitrix_sessid|ActionFilter\\\\Authentication|ActionFilter\\\\Csrf"),
    ("Loader", r"Loader::includeModule"),
    # --- folded-in safety patterns (the cheapest, highest-signal dangerous sinks) ---
    ("SAFETY: unserialize of request", r"unserialize\s*\(\s*\$_"),
    ("SAFETY: direct request echo", r"<\?=\s*\$_(GET|POST|REQUEST|COOKIE)"),
]

COMPILED = []
for _name, _src in _PATTERNS:
    try:
        COMPILED.append((_name, re.compile(_src)))
    except re.error as exc:  # pragma: no cover - keep the sweep running
        sys.stderr.write(f"[recon] skipped pattern {_name!r}: {exc}\n")


def is_vendored(rel):
    name = rel.lower()
    if ".min." in os.path.basename(name):
        return True
    if os.path.basename(name) in {"package-lock.json", "yarn.lock", "composer.lock", "poetry.lock"}:
        return True
    parts = name.replace("\\", "/").split("/")
    return any(p in {"vendor", "third_party", "node_modules"} for p in parts)


def decode_bytes(data):
    """utf-8 → cp1251 → latin-1. latin-1 never raises, so 1251 text is preserved."""
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def iter_target_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            if os.path.islink(full):
                continue
            suffix = os.path.splitext(fname)[1].lower()
            if suffix in BINARY_SUFFIXES:
                continue
            rel = os.path.relpath(full, root)
            if is_vendored(rel):
                continue
            # Restrict heavy regex work to text-ish files; unknown extensions are
            # scanned too (many Bitrix files have none) but obvious binaries skip.
            if suffix and suffix not in TEXT_SUFFIXES and suffix not in {""}:
                # allow unknown text extensions, skip the clearly-binary ones above
                pass
            yield full, rel


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: recon.py <module_dir>\n")
        return 2
    root = os.path.abspath(os.path.expanduser(sys.argv[1]))
    if not os.path.isdir(root):
        sys.stderr.write(f"[recon] not a directory: {root}\n")
        return 2

    hits = {name: [] for name, _ in _PATTERNS}
    truncated = set()
    target_files = []
    CODE_SUFFIXES = {".php", ".php5", ".php7", ".phtml", ".inc", ".tpl", ".html", ".htm", ".phps"}

    for full, rel in iter_target_files(root):
        try:
            if os.path.getsize(full) > MAX_FILE_BYTES:
                continue
            with open(full, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if b"\x00" in data[:4096]:  # binary guard for unknown extensions
            continue
        # Code-audit targets (for scannedFiles + the Phase-2 read list) are the
        # PHP/template files plus extensionless files (common in Bitrix modules);
        # other text files are still grepped for signals but not counted as audit
        # targets.
        suffix = os.path.splitext(rel)[1].lower()
        if suffix in CODE_SUFFIXES or suffix == "":
            target_files.append(rel)
        text = decode_bytes(data)
        lines = text.splitlines()
        for lineno, line in enumerate(lines, 1):
            for name, rx in COMPILED:
                bucket = hits[name]
                if len(bucket) >= MAX_MATCHES_PER_CATEGORY:
                    truncated.add(name)
                    continue
                if rx.search(line):
                    bucket.append(f"{rel}:{lineno}: {line.strip()[:240]}")

    rel_root = os.path.basename(root.rstrip("/")) or root
    print(f"# RECON for {rel_root}")
    print(f"# scannedFiles (PHP/template audit targets): {len(target_files)}")
    print("# (one deterministic pass; covers the Step 1.2 recon table + safety patterns)")

    # Full target-file inventory so Phase 2 needs no separate `find` round-trip.
    print(f"\n=== TARGET FILES ({len(target_files)}) ===")
    for rel in target_files:
        print(rel)

    total = 0
    for name, _ in _PATTERNS:
        bucket = hits[name]
        if not bucket:
            continue
        total += len(bucket)
        print(f"\n=== {name} ({len(bucket)}{'+' if name in truncated else ''}) ===")
        for row in bucket:
            print(row)
        if name in truncated:
            print(f"... [truncated at {MAX_MATCHES_PER_CATEGORY}; inspect this category manually]")
    if total == 0:
        print("\n(no recon signals matched — still audit entry points by reading files in full)")
    print(f"\n# total signal lines: {total} across {sum(1 for n,_ in _PATTERNS if hits[n])} categories")
    print(f"# NOTE: report scannedFiles = {len(target_files)} (TARGET FILES count above).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
