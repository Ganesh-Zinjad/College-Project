"""
AI Explain Service — Feature 2: Explainable AI for individual vulnerabilities.

Uses the configured LLM provider (Anthropic / OpenAI / Gemini) to generate a
structured, developer-friendly deep-dive on a detected vulnerability:
  • Root cause
  • Attack scenario (step-by-step)
  • Business impact
  • Fix walkthrough
  • Prevention tips
  • Related vulnerabilities to check nearby
  • Why the engine flagged this specific code block

The provider is selected by AI_PROVIDER in backend/.env — no code changes
needed when switching between Anthropic, OpenAI, and Gemini.
"""
import json
import logging

from app.models.vulnerability import Vulnerability
from app.services.llm_provider import get_llm_provider

logger = logging.getLogger("secure_code_platform.ai_explain")

EXPLAIN_SYSTEM_PROMPT = """You are a senior application security engineer explaining a vulnerability to a developer.
Your explanation must be specific to the code shown — avoid generic advice.
Write clearly, as if mentoring a junior developer.

Respond ONLY with a valid JSON object. No prose before or after. No markdown fences.
Use exactly these keys:
{
  "root_cause": "2-4 sentences. Why is this specific code pattern vulnerable? Reference the actual code.",
  "attack_scenario": "Step-by-step realistic attack. Include example malicious input and what the attacker achieves. Write each step on a new line starting with a number and period.",
  "business_impact": "2-3 sentences. Real-world consequences: data breach, privilege escalation, service disruption, regulatory risk, etc.",
  "fix_walkthrough": "Numbered steps to fix this specific issue. Reference the language/framework in the file.",
  "prevention_tips": ["Actionable tip 1", "Actionable tip 2", "Actionable tip 3", "Actionable tip 4"],
  "related_vulnerabilities": ["Related CWE or vulnerability class 1", "Related CWE or vulnerability class 2", "Related CWE or vulnerability class 3"],
  "confidence_explanation": "1-2 sentences. Why did the detection engine flag this particular code block?"
}"""


class AIExplainService:

    def explain(self, vuln: Vulnerability) -> dict:
        """
        Generate a structured explanation for a single vulnerability.

        Returns a dict with keys matching ExplainVulnerabilityResponse schema.
        Raises RuntimeError if the provider is not configured or the call fails.
        """
        # This will raise RuntimeError with a clear message if no key is set
        provider = get_llm_provider()

        logger.info(
            "Explaining vuln %s via %s (%s)", vuln.id, provider.name, provider.model_id
        )

        user_message = self._build_prompt(vuln)
        raw_text = provider.complete(
            system_prompt=EXPLAIN_SYSTEM_PROMPT,
            user_message=user_message,
            max_tokens=2048,
        )
        return self._parse_response(raw_text, vuln)

    # ------------------------------------------------------------------

    @staticmethod
    def _build_prompt(vuln: Vulnerability) -> str:
        lines = [
            f"Vulnerability: {vuln.title}",
            f"CWE ID: {vuln.cwe_id or 'Not classified'}",
            f"OWASP Category: {vuln.owasp_category or 'Not classified'}",
            f"Severity: {vuln.severity.value.upper()}",
            f"Risk Score: {vuln.risk_score}/10",
            f"Confidence: {vuln.confidence:.0%}",
            f"File: {vuln.file_path} (lines {vuln.line_start}–{vuln.line_end})",
            "",
            "Description:",
            vuln.description,
        ]
        if vuln.code_snippet:
            lines += ["", "Flagged code:", "```", vuln.code_snippet[:1000], "```"]
        if vuln.suggested_fix:
            lines += ["", "Current suggested fix:", vuln.suggested_fix]
        if vuln.secure_code_example:
            lines += ["", "Secure code example:", "```", vuln.secure_code_example[:600], "```"]
        lines += [
            "",
            f"Detected by: {vuln.source_engine.upper()} engine",
            "",
            "Provide a deep, developer-friendly explanation as described in your instructions.",
        ]
        return "\n".join(lines)

    @staticmethod
    def _parse_response(raw_text: str, vuln: Vulnerability) -> dict:
        cleaned = raw_text.strip()

        # Strip markdown fences
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()

        # Extract JSON object even if there's surrounding prose
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start != -1 and end > start:
            cleaned = cleaned[start:end]

        try:
            data = json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            logger.warning("AI explain returned non-JSON; using fallback structure")
            data = {
                "root_cause": raw_text[:500],
                "attack_scenario": "See description above.",
                "business_impact": f"Severity: {vuln.severity.value}",
                "fix_walkthrough": vuln.suggested_fix or "See suggested fix in the results.",
                "prevention_tips": [
                    f"Follow secure coding guidelines for {vuln.owasp_category or 'this vulnerability class'}"
                ],
                "related_vulnerabilities": [vuln.cwe_id] if vuln.cwe_id else [],
                "confidence_explanation": (
                    f"Flagged with {vuln.confidence:.0%} confidence by the {vuln.source_engine} engine."
                ),
            }

        # Fill in any missing keys with sensible defaults
        defaults = {
            "root_cause": "No explanation available.",
            "attack_scenario": "Not provided.",
            "business_impact": "Not provided.",
            "fix_walkthrough": vuln.suggested_fix or "Not provided.",
            "prevention_tips": [],
            "related_vulnerabilities": [],
            "confidence_explanation": f"Flagged by the {vuln.source_engine} engine.",
        }
        for key, default in defaults.items():
            if key not in data or not data[key]:
                data[key] = default

        # Ensure list fields are actually lists
        for key in ("prevention_tips", "related_vulnerabilities"):
            if isinstance(data[key], str):
                data[key] = [data[key]]

        return data
