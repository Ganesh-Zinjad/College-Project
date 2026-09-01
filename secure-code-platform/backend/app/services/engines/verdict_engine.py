"""
Verdict engine — the tribunal.

Runs every enabled engine (CodeQL / AI / ML) in sequence, collects each
one's verdict and findings, and applies the platform's core rule:

    A project is SECURE only if every *enabled* engine reports SECURE.
    Any engine reporting VULNERABLE makes the overall verdict VULNERABLE.
    An engine that errors out (e.g. AI auditor with no API key) does not
    get to vote either way — it is excluded from the unanimity check,
    but is still shown in the UI as "did not run" rather than silently
    ignored.

This file deliberately contains zero HTTP/DB code — it only knows about
`BaseEngine` implementations and returns plain dataclasses. `ScanService`
is the one that persists the outcome.
"""
from dataclasses import dataclass, field

from app.services.engines.ai_engine import AIAuditEngine
from app.services.engines.base_engine import BaseEngine, EngineRunResult, EngineVerdict, LogFn
from app.services.engines.codeql_engine import CodeQLEngine
from app.services.engines.ml_engine import MLEngine


@dataclass
class VerdictOutcome:
    final_verdict: str  # "secure" | "vulnerable"
    engine_results: list[EngineRunResult] = field(default_factory=list)
    security_score: float = 0.0   # 0-100, higher is better
    risk_score: float = 0.0       # 0-10, higher is worse


class VerdictEngine:
    """Looks up an engine instance by name and orchestrates a full triple-judge run."""

    _ENGINE_REGISTRY: dict[str, type[BaseEngine]] = {
        "codeql": CodeQLEngine,
        "ai": AIAuditEngine,
        "ml": MLEngine,
    }

    def run_all(
        self,
        *,
        files: list[dict],
        enabled_engines: dict[str, bool],
        target_cwe_ids: list[str],
        log: LogFn,
        on_engine_start=None,
        on_engine_done=None,
    ) -> VerdictOutcome:
        results: list[EngineRunResult] = []

        for engine_key, engine_cls in self._ENGINE_REGISTRY.items():
            if not enabled_engines.get(engine_key, True):
                log("info", f"Skipping {engine_key} (disabled for this scan)")
                continue

            if on_engine_start:
                on_engine_start(engine_key)

            engine: BaseEngine = engine_cls()
            log("info", f"Starting {engine_key} engine")
            result = engine.run(files, target_cwe_ids, log)
            results.append(result)

            if on_engine_done:
                on_engine_done(engine_key, result)

        outcome = self._aggregate(results)
        return outcome

    @staticmethod
    def _aggregate(results: list[EngineRunResult]) -> VerdictOutcome:
        voting_results = [r for r in results if r.verdict != EngineVerdict.ERROR]

        if not voting_results:
            final_verdict = "vulnerable"  # no engine could vote — fail safe, don't silently call it secure
        else:
            final_verdict = "secure" if all(r.verdict == EngineVerdict.SECURE for r in voting_results) else "vulnerable"

        # Security score: starts at 100, loses points per finding weighted by severity.
        # Floors at 0. A clean scan with zero findings scores 100.
        severity_penalty = {"low": 2, "medium": 6, "high": 12, "critical": 22}
        penalty = sum(severity_penalty.get(f.severity, 6) for r in results for f in r.findings)
        security_score = max(0.0, 100.0 - penalty)

        all_risk_scores = [f.risk_score for r in results for f in r.findings]
        risk_score = round(max(all_risk_scores), 1) if all_risk_scores else 0.0

        return VerdictOutcome(
            final_verdict=final_verdict,
            engine_results=results,
            security_score=round(security_score, 1),
            risk_score=risk_score,
        )
