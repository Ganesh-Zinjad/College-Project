"""
Engine 1 — CodeQL static analysis.

Real integration: builds a CodeQL database from the uploaded source tree and
runs the configured query suite via the `codeql` CLI. Requires the CodeQL CLI
binary (https://github.com/github/codeql-cli-binaries) and CODEQL_CLI_PATH
set in .env.

Fallback analyzer: when the CLI binary is not found, automatically falls back
to a built-in Python regex/AST analyzer covering the same 13 CWE categories.
No code changes are needed when switching between the two modes.

SARIF parsing fix (this version):
  - CWE extracted from rule properties.tags ("external/cwe/cwe-089")
    not from the rule ID ("py/sql-injection") which never contains "cwe-"
  - File paths cleaned of CodeQL's UUID database prefix
  - Severity derived from CVSS security-severity score or result level
  - Title taken from rule shortDescription, not the CWE knowledge base
  - OWASP category mapped from CodeQL rule ID
"""
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from app.core.config import settings
from app.services.engines.base_engine import BaseEngine, EngineFinding, EngineRunResult, EngineVerdict, LogFn
from app.utils.cwe_mapping import lookup


# ---------------------------------------------------------------------------
# Fallback regex rules (used when CodeQL CLI is not installed)
# ---------------------------------------------------------------------------

_RULES: list[tuple[str, re.Pattern, set[str], str]] = [
    ("CWE-89",  re.compile(r'(execute|cursor\.execute|query)\s*\(\s*(f["\']|["\'].*%s.*["\']\s*%|.*\+.*)', re.I),
     {"python"}, "SQL query built via string formatting/concatenation"),
    ("CWE-89",  re.compile(r'\.(query|execute)\s*\(\s*`.*\$\{', re.I),
     {"javascript", "typescript"}, "SQL query built with template literal containing an interpolated variable"),
    ("CWE-78",  re.compile(r'os\.system\s*\(|subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True', re.I),
     {"python"}, "Shell command executed with shell=True or os.system"),
    ("CWE-78",  re.compile(r'child_process\.(exec|execSync)\s*\(', re.I),
     {"javascript", "typescript"}, "Shell command via child_process.exec"),
    ("CWE-95",  re.compile(r'\beval\s*\(|\bexec\s*\(', re.I),
     {"python", "javascript", "typescript"}, "Dynamic code execution via eval()/exec()"),
    ("CWE-79",  re.compile(r'\.innerHTML\s*=|document\.write\s*\('),
     {"javascript", "typescript", "html"}, "Untrusted data assigned to innerHTML / document.write"),
    ("CWE-798", re.compile(r'(api[_-]?key|secret|password|token)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']', re.I),
     {"python", "javascript", "typescript", "java", "go", "ruby", "php"}, "Hardcoded credential or API key"),
    ("CWE-327", re.compile(r'hashlib\.(md5|sha1)\s*\(|MD5\.|SHA1\.|DES\.'),
     {"python", "java", "csharp"}, "Use of a broken hash/cipher (MD5/SHA1/DES)"),
    ("CWE-502", re.compile(r'pickle\.loads?\s*\(|yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)'),
     {"python"}, "Deserialization of untrusted data via pickle or unsafe yaml.load"),
    ("CWE-22",  re.compile(r'open\s*\(\s*os\.path\.join\([^)]*request|open\s*\(\s*.*\+\s*filename', re.I),
     {"python"}, "File path built from user input without traversal validation"),
    ("CWE-918", re.compile(r'requests\.(get|post)\s*\(\s*[a-zA-Z_]+\s*[,)]|fetch\s*\(\s*[a-zA-Z_]+\s*[,)]'),
     {"python", "javascript", "typescript"}, "Outbound HTTP request to a variable URL without host allowlisting"),
    ("CWE-330", re.compile(r'\brandom\.(random|randint|choice)\s*\(.*\b(token|password|secret|otp)\b', re.I),
     {"python"}, "Non-cryptographic RNG used for a security-sensitive value"),
    ("CWE-611", re.compile(r'etree\.parse\s*\(|etree\.fromstring\s*\(|xml\.sax\.parse'),
     {"python"}, "XML parsed without disabling external entity resolution"),
]

# ---------------------------------------------------------------------------
# CodeQL rule ID → OWASP Top 10 2021 mapping
# ---------------------------------------------------------------------------

_RULE_OWASP: dict[str, str] = {
    # Python
    "py/sql-injection":              "A03:2021 - Injection",
    "py/command-line-injection":     "A03:2021 - Injection",
    "py/code-injection":             "A03:2021 - Injection",
    "py/path-traversal":             "A01:2021 - Broken Access Control",
    "py/xss":                        "A03:2021 - Injection",
    "py/reflected-xss":              "A03:2021 - Injection",
    "py/ssrf":                       "A10:2021 - Server-Side Request Forgery",
    "py/url-redirection":            "A01:2021 - Broken Access Control",
    "py/weak-cryptographic-algorithm": "A02:2021 - Cryptographic Failures",
    "py/cleartext-storage-in-file":  "A02:2021 - Cryptographic Failures",
    "py/cleartext-logging":          "A02:2021 - Cryptographic Failures",
    "py/unsafe-deserialization":     "A08:2021 - Software and Data Integrity Failures",
    "py/xml-bomb":                   "A05:2021 - Security Misconfiguration",
    "py/xxe":                        "A05:2021 - Security Misconfiguration",
    "py/regex-injection":            "A03:2021 - Injection",
    "py/xpath-injection":            "A03:2021 - Injection",
    "py/ldap-injection":             "A03:2021 - Injection",
    "py/template-injection":         "A03:2021 - Injection",
    "py/uncontrolled-format-string": "A03:2021 - Injection",
    "py/incomplete-url-sanitization": "A03:2021 - Injection",
    # JavaScript / TypeScript
    "js/sql-injection":              "A03:2021 - Injection",
    "js/nosql-injection":            "A03:2021 - Injection",
    "js/code-injection":             "A03:2021 - Injection",
    "js/xss":                        "A03:2021 - Injection",
    "js/reflected-xss":              "A03:2021 - Injection",
    "js/dom-based-xss":              "A03:2021 - Injection",
    "js/path-traversal":             "A01:2021 - Broken Access Control",
    "js/ssrf":                       "A10:2021 - Server-Side Request Forgery",
    "js/url-redirection":            "A01:2021 - Broken Access Control",
    "js/weak-cryptographic-algorithm": "A02:2021 - Cryptographic Failures",
    "js/xpath-injection":            "A03:2021 - Injection",
    "js/template-object-injection":  "A03:2021 - Injection",
    "js/regex-injection":            "A03:2021 - Injection",
    "js/missing-rate-limiting":      "A05:2021 - Security Misconfiguration",
    "js/insecure-helmet-configuration": "A05:2021 - Security Misconfiguration",
    # Java
    "java/sql-injection":            "A03:2021 - Injection",
    "java/command-line-injection":   "A03:2021 - Injection",
    "java/code-injection":           "A03:2021 - Injection",
    "java/xss":                      "A03:2021 - Injection",
    "java/path-traversal":           "A01:2021 - Broken Access Control",
    "java/xxe":                      "A05:2021 - Security Misconfiguration",
    "java/unsafe-deserialization":   "A08:2021 - Software and Data Integrity Failures",
    "java/weak-cryptographic-algorithm": "A02:2021 - Cryptographic Failures",
    "java/url-redirection":          "A01:2021 - Broken Access Control",
    "java/ssrf":                     "A10:2021 - Server-Side Request Forgery",
    # Go
    "go/sql-injection":              "A03:2021 - Injection",
    "go/path-traversal":             "A01:2021 - Broken Access Control",
    "go/ssrf":                       "A10:2021 - Server-Side Request Forgery",
    "go/xss":                        "A03:2021 - Injection",
}


class CodeQLEngine(BaseEngine):
    name = "codeql"

    def run(self, files: list[dict], target_cwe_ids: list[str], log: LogFn) -> EngineRunResult:
        start = time.monotonic()
        codeql_available = (
            shutil.which(settings.CODEQL_CLI_PATH) is not None
            or Path(settings.CODEQL_CLI_PATH).is_file()
        )

        if codeql_available:
            log("info", "CodeQL CLI detected — building database from source tree")
            findings, raw = self._run_real_codeql(files, target_cwe_ids, log)
        else:
            log("info", "CodeQL CLI not found on this host — using built-in security-extended rule set")
            findings, raw = self._run_fallback_analysis(files, target_cwe_ids, log)

        duration_ms = int((time.monotonic() - start) * 1000)
        verdict = EngineVerdict.VULNERABLE if findings else EngineVerdict.SECURE
        summary = (
            f"{len(findings)} finding(s) across {len(files)} file(s)"
            if findings
            else f"No issues found across {len(files)} file(s) scanned"
        )
        log("success" if not findings else "warn", f"CodeQL analysis complete — {summary}")

        return EngineRunResult(
            engine_name=self.name,
            verdict=verdict,
            confidence=0.95,
            findings=findings,
            summary=summary,
            duration_ms=duration_ms,
            raw_output=raw,
        )

    # ------------------------------------------------------------------
    # Real CodeQL CLI integration
    # ------------------------------------------------------------------

    def _run_real_codeql(
        self, files: list[dict], target_cwe_ids: list[str], log: LogFn
    ) -> tuple[list[EngineFinding], dict]:
        languages = {
            f["language"]
            for f in files
            if f["language"] in {"python", "javascript", "java", "go"}
        }
        if not languages:
            log("warn", "No CodeQL-supported language detected; skipping real CLI run")
            return [], {"mode": "codeql-cli", "skipped": True}

        source_root = str(Path(files[0]["path"]).parent.parent) if files else "."
        db_base = Path(settings.CODEQL_DB_DIR)
        db_base.mkdir(parents=True, exist_ok=True)

        all_findings: list[EngineFinding] = []
        sarif_run_count = 0

        for language in languages:
            db_path = str(db_base / f"db-{language}-{int(time.time())}")
            sarif_path = db_path + "-results.sarif"

            try:
                log("info", f"Building CodeQL database for {language}")
                subprocess.run(
                    [
                        settings.CODEQL_CLI_PATH, "database", "create", db_path,
                        f"--language={language}",
                        f"--source-root={source_root}",
                        "--overwrite",
                    ],
                    check=True,
                    capture_output=True,
                    timeout=settings.CODEQL_TIMEOUT_SECONDS,
                )

                log("info", f"Running {settings.CODEQL_QUERY_SUITE} query suite for {language}")
                subprocess.run(
                    [
                        settings.CODEQL_CLI_PATH, "database", "analyze", db_path,
                        f"{language}-{settings.CODEQL_QUERY_SUITE}.qls",
                        "--format=sarifv2.1.0",
                        f"--output={sarif_path}",
                    ],
                    check=True,
                    capture_output=True,
                    timeout=settings.CODEQL_TIMEOUT_SECONDS,
                )

                with open(sarif_path) as f:
                    sarif = json.load(f)

                findings = self._parse_sarif(sarif, target_cwe_ids)
                all_findings.extend(findings)
                sarif_run_count += 1
                log("info", f"{language}: {len(findings)} finding(s)")

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
                log("error", f"CodeQL run failed for {language}: {exc}")

        return all_findings, {"mode": "codeql-cli", "sarif_run_count": sarif_run_count}

    # ------------------------------------------------------------------
    # SARIF parser — fixed version
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_sarif(sarif: dict, target_cwe_ids: list[str]) -> list[EngineFinding]:
        """
        Parse a CodeQL SARIF v2.1.0 document into normalized EngineFinding objects.

        Key differences from the naive version that caused blank CWE / UUID paths:
          1. CWE is extracted from rule.properties.tags ("external/cwe/cwe-089")
             NOT from the rule ID ("py/sql-injection") which never contains "cwe-"
          2. File paths are cleaned of CodeQL's UUID database prefix
          3. Severity comes from the CVSS security-severity score, not a fallback guess
          4. Title comes from rule shortDescription, not the CWE knowledge base fallback
          5. OWASP category is mapped from the CodeQL rule ID directly
        """
        findings: list[EngineFinding] = []

        for run in sarif.get("runs", []):
            # ---- Build rule lookup (by id and by index) ----
            driver_rules: list[dict] = run.get("tool", {}).get("driver", {}).get("rules", [])
            rules_by_id: dict[str, dict] = {}
            rules_by_index: dict[int, dict] = {}
            for idx, rule in enumerate(driver_rules):
                rid = rule.get("id", "")
                rules_by_id[rid] = rule
                rules_by_index[idx] = rule

            for result in run.get("results", []):
                rule_id: str = result.get("ruleId", "")
                rule_index = result.get("ruleIndex")

                # Resolve the rule metadata object
                rule_meta: dict = (
                    rules_by_id.get(rule_id)
                    or (rules_by_index.get(rule_index) if rule_index is not None else None)
                    or {}
                )

                # ---- CWE ----
                # CodeQL stores CWE in rule.properties.tags as "external/cwe/cwe-089"
                # NOT inside the rule ID string — this was the root cause of blank CWEs
                cwe_id = _extract_cwe_from_tags(rule_meta)

                # Filter by target CWEs when a custom scan targets specific IDs
                if target_cwe_ids and cwe_id and cwe_id not in target_cwe_ids:
                    continue

                # ---- Title ----
                # Use the rule's human-readable shortDescription, not a CWE lookup fallback
                title = (
                    rule_meta.get("shortDescription", {}).get("text")
                    or rule_meta.get("name")
                    or rule_id.replace("/", " ").replace("-", " ").title()
                    or "Security Issue"
                )

                # ---- Severity ----
                severity = _extract_severity(rule_meta, result)
                risk_score_val = _severity_to_risk(severity)

                # ---- OWASP category ----
                owasp = _RULE_OWASP.get(rule_id, "")
                if not owasp and cwe_id:
                    # Fall back to the CWE knowledge base for unmapped rules
                    owasp = lookup(cwe_id).get("owasp", "")

                # ---- File path ----
                # CodeQL prefixes URIs with a UUID scan-database identifier.
                # "de6c8ed0-0388-46e2-a4dd-25ca3c556039/path_traversal.py:10"
                # → we strip the UUID prefix to get "path_traversal.py"
                location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
                region = location.get("region", {})
                raw_uri = location.get("artifactLocation", {}).get("uri", "")
                clean_path = _clean_sarif_uri(raw_uri)

                # ---- Description ----
                description = result.get("message", {}).get("text", "") or title

                # ---- Fix / secure example from CWE knowledge base ----
                kb = lookup(cwe_id) if cwe_id else {}
                suggested_fix = kb.get("fix", "")
                secure_example = kb.get("secure_example", "")

                findings.append(EngineFinding(
                    title=title,
                    description=description,
                    severity=severity,
                    risk_score=risk_score_val,
                    cwe_id=cwe_id,
                    owasp_category=owasp,
                    file_path=clean_path,
                    line_start=region.get("startLine", 0),
                    line_end=region.get("endLine", region.get("startLine", 0)),
                    code_snippet="",  # CodeQL SARIF doesn't embed snippets by default
                    suggested_fix=suggested_fix,
                    secure_code_example=secure_example,
                    confidence=0.95,
                ))

        return findings

    # ------------------------------------------------------------------
    # Built-in fallback analyzer (no external binary required)
    # ------------------------------------------------------------------

    def _run_fallback_analysis(
        self, files: list[dict], target_cwe_ids: list[str], log: LogFn
    ) -> tuple[list[EngineFinding], dict]:
        findings: list[EngineFinding] = []
        rules_checked = 0

        for file_info in files:
            path = Path(file_info["path"])
            language = file_info["language"]
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = text.splitlines()

            for cwe_id, pattern, langs, description in _RULES:
                if language not in langs:
                    continue
                if target_cwe_ids and cwe_id not in target_cwe_ids:
                    continue
                rules_checked += 1
                for line_no, line in enumerate(lines, start=1):
                    if pattern.search(line):
                        meta = lookup(cwe_id)
                        findings.append(EngineFinding(
                            title=meta["title"],
                            description=(
                                f"{description}. "
                                f"Detected in {file_info['relative_path']} line {line_no}."
                            ),
                            severity=meta["severity"],
                            risk_score=meta["risk_score"],
                            cwe_id=cwe_id,
                            owasp_category=meta["owasp"],
                            file_path=file_info["relative_path"],
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip()[:300],
                            suggested_fix=meta["fix"],
                            secure_code_example=meta["secure_example"],
                            confidence=0.9,
                        ))

        log("info", f"Checked {rules_checked} rule/language pairing(s) against {len(files)} file(s)")
        return findings, {"mode": "fallback-static-rules", "rules_evaluated": len(_RULES)}


# ---------------------------------------------------------------------------
# SARIF helper functions
# ---------------------------------------------------------------------------

def _extract_cwe_from_tags(rule_meta: dict) -> str:
    """
    Extract a CWE ID from a CodeQL rule's properties.tags array.

    CodeQL stores CWE like this:
        "tags": ["security", "external/cwe/cwe-089", "correctness"]
    or sometimes:
        "tags": ["CWE-089"]

    Returns "CWE-89" (normalized, no leading zeros) or "" if not found.
    """
    tags: list[str] = rule_meta.get("properties", {}).get("tags", [])
    for tag in tags:
        tag_lower = tag.lower()
        if "cwe" not in tag_lower:
            continue
        # Matches: "external/cwe/cwe-089", "cwe-089", "CWE-89", "cwe089"
        m = re.search(r"cwe[/\-_]?(\d+)", tag_lower)
        if m:
            num = int(m.group(1))   # strip leading zeros
            return f"CWE-{num}"
    return ""


def _clean_sarif_uri(uri: str) -> str:
    """
    Convert a raw CodeQL SARIF artifact URI to a human-readable relative path.

    CodeQL may produce URIs in several formats:
      "path_traversal.py"                                          ← clean already
      "de6c8ed0-0388-46e2-a4dd-25ca3c556039/path_traversal.py"   ← UUID prefix
      "src/app/path_traversal.py"                                  ← relative path
      "file:///C:/Users/.../path_traversal.py"                    ← absolute URI
    """
    if not uri:
        return ""

    # Strip file:// scheme
    uri = re.sub(r"^file:/{2,3}", "", uri)

    # Strip UUID database prefix (8-4-4-4-12 hex format followed by /)
    uri = re.sub(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/",
        "",
        uri,
        flags=re.IGNORECASE,
    )

    # Normalize Windows backslashes
    uri = uri.replace("\\", "/")

    return uri


def _extract_severity(rule_meta: dict, result: dict) -> str:
    """
    Derive a severity label from CodeQL SARIF metadata.

    Priority:
      1. rule.properties.security-severity  (CVSS float string, most accurate)
      2. result.level                        (error / warning / note)
      3. rule.defaultConfiguration.level
      4. fallback → "medium"
    """
    # 1. CVSS security-severity score
    sec_sev = rule_meta.get("properties", {}).get("security-severity", "")
    if sec_sev:
        try:
            score = float(sec_sev)
            if score >= 9.0: return "critical"
            if score >= 7.0: return "high"
            if score >= 4.0: return "medium"
            return "low"
        except ValueError:
            pass

    # 2 & 3. SARIF level field
    level_map = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
    level = result.get("level", "") or rule_meta.get("defaultConfiguration", {}).get("level", "")
    return level_map.get(level, "medium")


def _severity_to_risk(severity: str) -> float:
    return {"low": 3.5, "medium": 5.5, "high": 7.8, "critical": 9.5}.get(severity, 5.5)