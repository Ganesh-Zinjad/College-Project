"""Dashboard endpoint: aggregate stats, trend data, and recent scans for the logged-in user."""
from collections import defaultdict

from fastapi import APIRouter

from app.core.dependencies import CurrentUser, DbSession
from app.models.scan import ScanStatus, Verdict
from app.repositories.scan_repository import ScanRepository
from app.schemas.scan import DashboardStatsOut, ScanHistoryItem

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStatsOut)
def get_dashboard_stats(current_user: CurrentUser, db: DbSession):
    repo = ScanRepository(db)

    total_scans = repo.count_for_owner(current_user.id)
    secure = repo.count_by_verdict(current_user.id, Verdict.SECURE)
    vulnerable = repo.count_by_verdict(current_user.id, Verdict.VULNERABLE)
    completed = secure + vulnerable
    detection_accuracy = round((secure / completed) * 100, 1) if completed else 0.0

    recent = repo.recent_for_owner(current_user.id, limit=6)
    recent_items = [
        ScanHistoryItem(
            id=s.id, name=s.name, status=s.status.value, verdict=s.verdict.value, scan_type=s.scan_type.value,
            security_score=s.security_score, total_files=s.total_files,
            vulnerability_count=repo.vulnerability_count(s.id),
            created_at=s.created_at, completed_at=s.completed_at,
        )
        for s in recent
    ]

    # Build a 14-day trend series from completed scans.
    all_scans = repo.scans_per_day(current_user.id)
    by_day: dict[str, dict] = defaultdict(lambda: {"total": 0, "secure": 0, "vulnerable": 0})
    for s in all_scans:
        if s.status != ScanStatus.COMPLETED:
            continue
        day = s.created_at.strftime("%Y-%m-%d")
        by_day[day]["total"] += 1
        by_day[day][s.verdict.value] += 1
    trend = [{"date": day, **counts} for day, counts in sorted(by_day.items())][-14:]

    severity_dist = repo.org_severity_distribution(current_user.id)

    return DashboardStatsOut(
        total_scans=total_scans,
        secure_projects=secure,
        vulnerable_projects=vulnerable,
        detection_accuracy=detection_accuracy,
        average_security_score=repo.average_security_score(current_user.id),
        total_vulnerabilities_found=repo.total_vulnerabilities_for_owner(current_user.id),
        critical_vulnerabilities=repo.critical_vulnerability_count(current_user.id),
        scans_trend=trend,
        severity_distribution=severity_dist,
        recent_scans=recent_items,
    )
