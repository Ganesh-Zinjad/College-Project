"""Admin-only schemas: platform-wide analytics and system monitoring."""
from pydantic import BaseModel


class SystemHealthOut(BaseModel):
    api_status: str
    database_status: str
    codeql_engine_status: str
    ai_engine_status: str
    ml_engine_status: str
    uptime_seconds: float
    total_users: int
    total_scans: int
    storage_used_mb: float


class AdminAnalyticsOut(BaseModel):
    total_users: int
    active_users: int
    total_scans: int
    scans_today: int
    overall_secure_rate: float
    total_vulnerabilities: int
    severity_distribution: list[dict]
    engine_usage: list[dict]   # [{engine, scans_run, avg_duration_ms}]
    top_cwe_categories: list[dict]


class AdminScanLogItem(BaseModel):
    id: str
    name: str
    owner_email: str
    status: str
    verdict: str
    created_at: str
