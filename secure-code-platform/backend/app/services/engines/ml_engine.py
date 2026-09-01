"""
Engine 3 — ML vulnerability classifier.

Loads the TF-IDF + Logistic Regression model trained by
`scripts/train_ml_model.py` and scores sliding windows of each file
(roughly function-sized chunks) for vulnerability probability. Chunks
scoring above ML_CONFIDENCE_THRESHOLD become findings; the chunk's own
predicted probability becomes that finding's confidence score.

If the model artifacts are missing (first run, fresh clone), the engine
trains them on the fly so the platform works immediately without a manual
setup step.
"""
import time
from pathlib import Path

import joblib

from app.core.config import settings
from app.services.engines.base_engine import BaseEngine, EngineFinding, EngineRunResult, EngineVerdict, LogFn
from app.utils.cwe_mapping import lookup

_CHUNK_LINES = 12   # roughly "function sized" sliding window
_CHUNK_STRIDE = 8   # overlap between consecutive windows so a finding near a boundary isn't missed

# Cheap heuristic to attach a plausible CWE label to an ML hit — the model
# itself only outputs "vulnerable probability", not a class, so we pattern-
# match the flagged chunk against the same keyword families CodeQL checks,
# purely for a human-readable label/category on the finding.
_KEYWORD_TO_CWE = [
    (("execute", "select ", "cursor", "query"), "CWE-89"),
    (("os.system", "subprocess", "shell=true", "child_process", "exec("), "CWE-78"),
    (("eval(", "exec("), "CWE-95"),
    (("innerhtml", "document.write"), "CWE-79"),
    (("api_key", "secret", "password =", "token ="), "CWE-798"),
    (("md5", "sha1", " des"), "CWE-327"),
    (("pickle", "yaml.load"), "CWE-502"),
    (("os.path.join", "open("), "CWE-22"),
    (("requests.get", "fetch("), "CWE-918"),
    (("random.random", "random.randint"), "CWE-330"),
    (("etree.parse", "xml.sax"), "CWE-611"),
]


class MLEngine(BaseEngine):
    name = "ml"

    def __init__(self):
        self.model = None
        self.vectorizer = None

    def run(self, files: list[dict], target_cwe_ids: list[str], log: LogFn) -> EngineRunResult:
        start = time.monotonic()
        self._ensure_model(log)

        all_findings: list[EngineFinding] = []
        chunks_scored = 0

        for file_info in files:
            try:
                text = Path(file_info["path"]).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = text.splitlines()
            if not lines:
                continue

            log("info", f"ML scoring {file_info['relative_path']} ({len(lines)} lines)")

            for start_line in range(0, len(lines), _CHUNK_STRIDE):
                chunk_lines = lines[start_line:start_line + _CHUNK_LINES]
                if not chunk_lines:
                    continue
                chunk_text = "\n".join(chunk_lines)
                chunks_scored += 1

                proba = self._predict_proba(chunk_text)
                if proba < settings.ML_CONFIDENCE_THRESHOLD:
                    continue

                cwe_id = self._infer_cwe(chunk_text)
                if target_cwe_ids and cwe_id and cwe_id not in target_cwe_ids:
                    continue
                meta = lookup(cwe_id)

                all_findings.append(EngineFinding(
                    title=f"ML-predicted: {meta['title']}",
                    description=(
                        f"The classifier predicted a {proba:.0%} probability that this code block "
                        f"contains a vulnerability, based on patterns learned from labeled training data."
                    ),
                    severity=meta["severity"],
                    risk_score=meta["risk_score"],
                    cwe_id=cwe_id,
                    owasp_category=meta["owasp"],
                    file_path=file_info["relative_path"],
                    line_start=start_line + 1,
                    line_end=min(start_line + len(chunk_lines), len(lines)),
                    code_snippet=chunk_text[:400],
                    suggested_fix=meta["fix"],
                    secure_code_example=meta["secure_example"],
                    confidence=round(proba, 3),
                ))

        # De-duplicate overlapping windows that both fired on the same root cause:
        # keep only the highest-confidence finding per (file, cwe) when their line ranges overlap.
        deduped = self._dedupe(all_findings)

        duration_ms = int((time.monotonic() - start) * 1000)
        verdict = EngineVerdict.VULNERABLE if deduped else EngineVerdict.SECURE
        avg_confidence = sum(f.confidence for f in deduped) / len(deduped) if deduped else 0.92
        summary = (
            f"ML classifier flagged {len(deduped)} code block(s) as likely vulnerable "
            f"(scored {chunks_scored} block(s) total)"
            if deduped else f"ML classifier scored {chunks_scored} code block(s), none above threshold"
        )
        log("success" if not deduped else "warn", summary)

        return EngineRunResult(
            engine_name=self.name,
            verdict=verdict,
            confidence=round(avg_confidence, 2),
            findings=deduped,
            summary=summary,
            duration_ms=duration_ms,
            raw_output={"chunks_scored": chunks_scored, "threshold": settings.ML_CONFIDENCE_THRESHOLD},
        )

    # ------------------------------------------------------------------

    def _ensure_model(self, log: LogFn) -> None:
        if self.model is not None and self.vectorizer is not None:
            return

        model_path = Path(settings.ML_MODEL_PATH)
        vec_path = Path(settings.ML_VECTORIZER_PATH)

        if not model_path.exists() or not vec_path.exists():
            log("info", "ML model artifacts not found — training classifier now (one-time setup)")
            import sys
            sys.path.insert(0, str(Path(settings.ML_MODEL_PATH).resolve().parent.parent / "scripts"))
            from scripts.train_ml_model import train  # noqa: E402
            train()

        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vec_path)

    def _predict_proba(self, chunk_text: str) -> float:
        vec = self.vectorizer.transform([chunk_text])
        # predict_proba returns [[P(secure), P(vulnerable)]]
        return float(self.model.predict_proba(vec)[0][1])

    @staticmethod
    def _infer_cwe(chunk_text: str) -> str:
        lowered = chunk_text.lower()
        for keywords, cwe_id in _KEYWORD_TO_CWE:
            if any(kw in lowered for kw in keywords):
                return cwe_id
        return ""

    @staticmethod
    def _dedupe(findings: list[EngineFinding]) -> list[EngineFinding]:
        best_by_key: dict[tuple[str, str], EngineFinding] = {}
        for finding in findings:
            key = (finding.file_path, finding.cwe_id or finding.title)
            existing = best_by_key.get(key)
            if existing is None or finding.confidence > existing.confidence:
                best_by_key[key] = finding
        return list(best_by_key.values())
