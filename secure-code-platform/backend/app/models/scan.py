"""Scan model — a single scan job (one or many files) and its lifecycle."""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Enum as SAEnum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanType(str, enum.Enum):
    FULL = "full"
    QUICK = "quick"
    CUSTOM = "custom"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Verdict(str, enum.Enum):
    SECURE = "secure"
    VULNERABLE = "vulnerable"
    PENDING = "pending"


class Scan(Base):
    """
    One scan job. Holds the overall configuration, lifecycle status, and the
    rolled-up result of all three engines. Per-engine detail lives in
    `EngineResult`; individual findings live in `Vulnerability`.
    """
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(SAEnum(ScanType), default=ScanType.FULL, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.QUEUED, nullable=False)
    verdict: Mapped[Verdict] = mapped_column(SAEnum(Verdict), default=Verdict.PENDING, nullable=False)

    # Engine toggles, chosen at scan-config time
    engine_codeql_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    engine_ai_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    engine_ml_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Custom-scan targeting: comma-separated CWE/CVE ids, or empty = "all"
    target_cwe_ids: Mapped[str] = mapped_column(String(500), default="", nullable=False)

    total_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_lines: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_engine: Mapped[str] = mapped_column(String(50), default="", nullable=False)

    security_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # 0-100
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)       # 0-10

    error_message: Mapped[str] = mapped_column(Text, default="", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    owner = relationship("User", back_populates="scans")
    files = relationship("ScanFile", back_populates="scan", cascade="all, delete-orphan")
    engine_results = relationship("EngineResult", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan", order_by="ScanLog.created_at")


class ScanFile(Base):
    """A single source file that belongs to a scan (extracted from zip/folder upload, or a direct upload)."""
    __tablename__ = "scan_files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    relative_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    language: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    line_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    scan = relationship("Scan", back_populates="files")


class EngineResult(Base):
    """The rolled-up verdict + metadata from a single engine (CodeQL / AI / ML) for one scan."""
    __tablename__ = "engine_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    engine_name: Mapped[str] = mapped_column(String(50), nullable=False)  # codeql | ai | ml
    verdict: Mapped[Verdict] = mapped_column(SAEnum(Verdict), default=Verdict.PENDING, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # 0-1, mainly used by ML
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    raw_output: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    scan = relationship("Scan", back_populates="engine_results")


class ScanLog(Base):
    """Append-only live-log line shown in the scan progress view / streamed over the websocket."""
    __tablename__ = "scan_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    engine_name: Mapped[str] = mapped_column(String(50), default="system", nullable=False)
    level: Mapped[str] = mapped_column(String(20), default="info", nullable=False)  # info | warn | error | success
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    scan = relationship("Scan", back_populates="logs")
