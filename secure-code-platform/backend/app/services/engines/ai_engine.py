"""
Engine 2 — AI Security Auditor.

Sends each source file to the configured LLM provider (Anthropic Claude,
OpenAI GPT, or Google Gemini — set AI_PROVIDER in .env) with a strict
security-review prompt and parses back a structured JSON list of findings.

If no provider is configured (API key missing), the engine logs a clear
warning and returns an ERROR-flavoured result rather than fabricating output.

Prompt contract — the model must respond with a JSON array. Each element:
  {
    "title":            short vulnerability name,
    "description":      1-3 sentences: issue + impact,
    "severity":         "low" | "medium" | "high" | "critical",
    "cwe_id":           e.g. "CWE-89" (or ""),
    "owasp_category":   e.g. "A03:2021 - Injection" (or ""),
    "line_start":       integer,
    "line_end":         integer,
    "suggested_fix":    concrete remediation,
    "secure_code_example": corrected code snippet,
    "confidence":       float 0-1
  }
Empty file → respond with [].
"""
import json
import time

from app.core.config import settings
from app.services.engines.base_engine import (
    BaseEngine,
    EngineFinding,
    EngineRunResult,
    EngineVerdict,
    LogFn,
)
from app.services.llm_provider import get_llm_provider, is_any_provider_configured

SYSTEM_PROMPT = """You are a senior application security auditor performing a manual code review.
You analyze source code for real, exploitable security vulnerabilities — not style issues.

For every vulnerability you find, be specific about the exact line number(s), explain the
real-world impact, and propose a concrete fix with a corrected code example.

Respond with ONLY a JSON array (no prose, no markdown fences). Each element must have exactly these keys:
  "title": short vulnerability name
  "description": 1-3 sentence explanation of the issue and its impact
  "severity": one of "low" | "medium" | "high" | "critical"
  "cwe_id": e.g. "CWE-89" (best matching CWE, or "" if none fits well)
  "owasp_category": e.g. "A03:2021 - Injection"
  "line_start": integer line number where the issue begins
  "line_end": integer line number where the issue ends
  "suggested_fix": concrete remediation advice, 1-3 sentences
  "secure_code_example": a short corrected code snippet
  "confidence": float 0-1, your confidence this is a real exploitable issue

If the file has no security issues, respond with an empty JSON array: []"""


class AIAuditEngine(BaseEngine):
    name = "ai"

    def run(self, files: list[dict], target_cwe_ids: list[str], log: LogFn) -> EngineRunResult:
        start = time.monotonic()

        # Check whether any provider is configured before doing any work
        if not is_any_provider_configured():
            log("warn",
                f"AI auditor skipped — no API key found for provider '{settings.active_ai_provider}'. "
                f"Set {settings.active_ai_provider.upper()}_API_KEY in backend/.env to enable it.")
            return EngineRunResult(
                engine_name=self.name,
                verdict=EngineVerdict.ERROR,
                confidence=0.0,
                findings=[],
                summary=f"AI auditor skipped: no API key configured for provider '{settings.active_ai_provider}'",
                duration_ms=int((time.monotonic() - start) * 1000),
                raw_output={"error": "missing_api_key", "provider": settings.active_ai_provider},
            )

        # Instantiate the configured provider (Anthropic / OpenAI / Gemini)
        try:
            provider = get_llm_provider()
        except RuntimeError as exc:
            log("error", f"AI auditor — provider init failed: {exc}")
            return EngineRunResult(
                engine_name=self.name,
                verdict=EngineVerdict.ERROR,
                confidence=0.0,
                findings=[],
                summary=f"AI auditor skipped: {exc}",
                duration_ms=int((time.monotonic() - start) * 1000),
                raw_output={"error": str(exc)},
            )

        log("info", f"AI auditor using provider: {provider.name} ({provider.model_id})")

        all_findings: list[EngineFinding] = []
        files_with_errors = 0

        for file_info in files:
            log("info", f"AI reviewing {file_info['relative_path']}")
            try:
                code_text = open(file_info["path"], encoding="utf-8", errors="ignore").read()
            except OSError:
                continue

            # Cap very large files so a single file can't exhaust the token budget
            truncated = code_text[:20_000]
            user_message = (
                f"File: {file_info['relative_path']}\n"
                f"Language: {file_info['language']}\n\n"
                f"```\n{truncated}\n```"
            )
            if target_cwe_ids:
                user_message += f"\n\nFocus specifically on these CWE categories: {', '.join(target_cwe_ids)}"

            try:
                raw_text = provider.complete(
                    system_prompt=SYSTEM_PROMPT,
                    user_message=user_message,
                    max_tokens=settings.AI_AUDIT_MAX_TOKENS,
                )
                file_findings = self._parse_findings(raw_text, file_info["relative_path"], code_text)
                all_findings.extend(file_findings)
            except Exception as exc:
                # Network / API errors must not crash the whole scan
                files_with_errors += 1
                log("error", f"AI review failed for {file_info['relative_path']}: {exc}")

        duration_ms = int((time.monotonic() - start) * 1000)
        verdict = EngineVerdict.VULNERABLE if all_findings else EngineVerdict.SECURE
        avg_confidence = (
            sum(f.confidence for f in all_findings) / len(all_findings)
            if all_findings else 0.9
        )
        summary = (
            f"{provider.name} flagged {len(all_findings)} issue(s)"
            if all_findings
            else f"{provider.name} found no issues across {len(files)} file(s)"
        )
        if files_with_errors:
            summary += f" ({files_with_errors} file(s) could not be reviewed)"
        log("success" if not all_findings else "warn", summary)

        return EngineRunResult(
            engine_name=self.name,
            verdict=verdict,
            confidence=round(avg_confidence, 2),
            findings=all_findings,
            summary=summary,
            duration_ms=duration_ms,
            raw_output={
                "provider": provider.name,
                "model": provider.model_id,
                "files_reviewed": len(files) - files_with_errors,
            },
        )

    # ------------------------------------------------------------------
    # JSON response parsing (shared by all providers)
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_findings(raw_text: str, relative_path: str, source_code: str) -> list[EngineFinding]:
        cleaned = raw_text.strip()

        # Strip markdown fences if the model ignores the "no fences" instruction
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()

        # Extract the JSON array even if there's surrounding prose
        start = cleaned.find("[")
        end = cleaned.rfind("]") + 1
        if start != -1 and end > start:
            cleaned = cleaned[start:end]

        try:
            items = json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            return []

        source_lines = source_code.splitlines()
        findings: list[EngineFinding] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            line_start = int(item.get("line_start") or 0)
            line_end = int(item.get("line_end") or line_start)
            snippet = ""
            if 0 < line_start <= len(source_lines):
                snippet = "\n".join(
                    source_lines[max(0, line_start - 1):min(len(source_lines), line_end)]
                )[:500]

            raw_severity = item.get("severity", "medium")
            severity = raw_severity if raw_severity in {"low", "medium", "high", "critical"} else "medium"

            findings.append(EngineFinding(
                title=str(item.get("title", "AI-detected issue"))[:255],
                description=str(item.get("description", "")),
                severity=severity,
                risk_score=_severity_to_risk_score(severity),
                cwe_id=str(item.get("cwe_id", "")),
                owasp_category=str(item.get("owasp_category", "")),
                file_path=relative_path,
                line_start=line_start,
                line_end=line_end,
                code_snippet=snippet,
                suggested_fix=str(item.get("suggested_fix", "")),
                secure_code_example=str(item.get("secure_code_example", "")),
                confidence=float(item.get("confidence", 0.85)),
            ))

        return findings


def _severity_to_risk_score(severity: str) -> float:
    return {"low": 3.5, "medium": 5.5, "high": 7.8, "critical": 9.5}.get(severity, 5.5)
