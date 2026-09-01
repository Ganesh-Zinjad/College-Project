"""Request/response schemas for scan configuration, progress, and results."""
from datetime import datetime
from typing import List

from pydantic import BaseModel, Field


# --- Upload ---

class UploadedFileOut(BaseModel):
    id: str
    filename: str
    relative_path: str
    language: str
    size_bytes: int
    line_count: int

    model_config = {"from_attributes": True}


class SkippedFileOut(BaseModel):
    """A file that was automatically filtered out because it can't be scanned."""
    filename: str
    reason: str


class UploadResponse(BaseModel):
    scan_id: str
    files: List[UploadedFileOut]
    total_files: int
    total_lines: int
    # Feature 1: list of auto-filtered files shown in the UI
    skipped_files: List[SkippedFileOut] = []
    total_skipped: int = 0


# --- Scan configuration ---

class ScanConfigRequest(BaseModel):
    scan_id: str
    name: str = Field(min_length=1, max_length=255)
    scan_type: str = Field(default="full", pattern="^(full|quick|custom)$")
    engine_codeql_enabled: bool = True
    engine_ai_enabled: bool = True
    engine_ml_enabled: bool = True
    # Comma-separated CWE/CVE ids; only used when scan_type == "custom". Empty = scan everything.
    target_cwe_ids: str = ""


class ScanStartResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# --- Scan progress ---

class ScanLogOut(BaseModel):
    engine_name: str
    level: str
    message: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanProgressOut(BaseModel):
    scan_id: str
    status: str
    progress_percent: int
    current_engine: str
    verdict: str
    logs: List[ScanLogOut]


# --- Results ---

class EngineResultOut(BaseModel):
    engine_name: str
    verdict: str
    confidence: float
    findings_count: int
    duration_ms: int
    summary: str

    model_config = {"from_attributes": True}


class VulnerabilityOut(BaseModel):
    id: str
    source_engine: str
    title: str
    description: str
    severity: str
    risk_score: float
    cwe_id: str
    cve_id: str
    owasp_category: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    suggested_fix: str
    secure_code_example: str
    confidence: float

    model_config = {"from_attributes": True}


class ScanResultOut(BaseModel):
    scan_id: str
    name: str
    status: str
    verdict: str
    scan_type: str
    security_score: float
    risk_score: float
    total_files: int
    total_lines: int
    created_at: datetime
    completed_at: datetime | None
    engine_results: List[EngineResultOut]
    vulnerabilities: List[VulnerabilityOut]
    severity_breakdown: dict


# --- Feature 2: Explainable AI response ---

class ExplainVulnerabilityResponse(BaseModel):
    vuln_id: str
    title: str
    root_cause: str
    attack_scenario: str
    business_impact: str
    fix_walkthrough: str
    prevention_tips: List[str]
    related_vulnerabilities: List[str]
    confidence_explanation: str
    generated_by: str = "Claude AI"


# --- History ---

class ScanHistoryItem(BaseModel):
    id: str
    name: str
    status: str
    verdict: str
    scan_type: str
    security_score: float
    total_files: int
    vulnerability_count: int
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class PaginatedScanHistory(BaseModel):
    items: List[ScanHistoryItem]
    total: int
    page: int
    page_size: int
    total_pages: int


# --- Dashboard ---

class DashboardStatsOut(BaseModel):
    total_scans: int
    secure_projects: int
    vulnerable_projects: int
    detection_accuracy: float
    average_security_score: float
    total_vulnerabilities_found: int
    critical_vulnerabilities: int
    scans_trend: List[dict]
    severity_distribution: List[dict]
    recent_scans: List[ScanHistoryItem]
