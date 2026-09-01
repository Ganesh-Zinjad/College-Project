"""
Base engine contract.

Every judge (CodeQL / AI / ML) implements the same interface so
`VerdictEngine` can orchestrate them uniformly: run each enabled engine,
collect a normalized `EngineFinding` list, and only declare SECURE if every
enabled engine agrees. This is the Strategy pattern — engines are
interchangeable implementations selected at scan-config time.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class EngineVerdict(str, Enum):
    SECURE = "secure"
    VULNERABLE = "vulnerable"
    ERROR = "error"


@dataclass
class EngineFinding:
    """One normalized vulnerability finding, shape-compatible with the Vulnerability ORM model."""
    title: str
    description: str
    severity: str               # low | medium | high | critical
    risk_score: float           # 0-10
    cwe_id: str = ""
    cve_id: str = ""
    owasp_category: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    suggested_fix: str = ""
    secure_code_example: str = ""
    confidence: float = 1.0


@dataclass
class EngineRunResult:
    """What an engine hands back to the orchestrator after running."""
    engine_name: str
    verdict: EngineVerdict
    confidence: float                 # 0-1, the engine's confidence in its own verdict
    findings: list[EngineFinding] = field(default_factory=list)
    summary: str = ""
    duration_ms: int = 0
    raw_output: dict = field(default_factory=dict)


# A log_fn callback lets engines stream progress lines back to the scan's
# live log / websocket without depending on the scan service or DB directly.
LogFn = Callable[[str, str], None]  # (level, message) -> None


class BaseEngine(ABC):
    """Abstract judge. Subclasses implement `run()`; `name` identifies the engine in results/UI."""

    name: str = "base"

    @abstractmethod
    def run(self, files: list[dict], target_cwe_ids: list[str], log: LogFn) -> EngineRunResult:
        """
        Args:
            files: list of {"path": absolute_path, "relative_path": str, "language": str}
            target_cwe_ids: CWE/CVE ids to restrict the scan to (empty list = scan everything)
            log: callback to emit a live progress line, e.g. log("info", "Building database...")
        """
        raise NotImplementedError
