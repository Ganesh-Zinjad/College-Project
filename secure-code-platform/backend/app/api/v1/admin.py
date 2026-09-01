"""
Admin endpoints — gated by `AdminUser` (role == admin), used by the Admin
panel for user management, scan log auditing, platform-wide analytics, and
system/engine health monitoring.
"""
import math
import time
from pathlib import Path

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.core.config import settings
from app.core.dependencies import AdminUser, DbSession
from app.core.exceptions import ForbiddenError, NotFoundError, ValidationFailedError
from app.models.scan import EngineResult, Scan, ScanStatus, Verdict
from app.models.user import User, UserRole
from app.models.vulnerability import Vulnerability
from app.repositories.scan_repository import ScanRepository
from app.repositories.user_repository import UserRepository
from app.schemas.admin import AdminAnalyticsOut, AdminScanLogItem, SystemHealthOut
from app.schemas.user import AdminUpdateUserRequest, AdminUserListItem

router = APIRouter(prefix="/admin", tags=["Admin"])

_PROCESS_START = time.monotonic()


# --- User management ---

@router.get("/users", response_model=list[AdminUserListItem])
def list_users(admin: AdminUser, db: DbSession, search: str = Query(default=""), page: int = Query(default=1, ge=1)):
    repo = UserRepository(db)
    users, _ = repo.list_all(search=search, page=page, page_size=50)
    return [
        AdminUserListItem(
            id=u.id, full_name=u.full_name, email=u.email, role=u.role.value, is_active=u.is_active,
            is_email_verified=u.is_email_verified, avatar_color=u.avatar_color, created_at=u.created_at,
            last_login_at=u.last_login_at, total_scans=repo.scan_count_for_user(u.id),
        )
        for u in users
    ]


@router.patch("/users/{user_id}", response_model=AdminUserListItem)
def update_user(user_id: str, payload: AdminUpdateUserRequest, admin: AdminUser, db: DbSession):
    repo = UserRepository(db)
    user = repo.get_by_id(user_id)
    if user is None:
        raise NotFoundError("User not found")
    if user.id == admin.id and payload.is_active is False:
        raise ValidationFailedError("You cannot deactivate your own account")

    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.role is not None:
        if payload.role not in {r.value for r in UserRole}:
            raise ValidationFailedError("Invalid role")
        user.role = UserRole(payload.role)

    repo.save(user)
    return AdminUserListItem(
        id=user.id, full_name=user.full_name, email=user.email, role=user.role.value, is_active=user.is_active,
        is_email_verified=user.is_email_verified, avatar_color=user.avatar_color, created_at=user.created_at,
        last_login_at=user.last_login_at, total_scans=repo.scan_count_for_user(user.id),
    )


@router.delete("/users/{user_id}")
def delete_user(user_id: str, admin: AdminUser, db: DbSession):
    if user_id == admin.id:
        raise ForbiddenError("You cannot delete your own account")
    repo = UserRepository(db)
    user = repo.get_by_id(user_id)
    if user is None:
        raise NotFoundError("User not found")
    repo.delete(user)
    return {"success": True, "message": "User deleted"}


# --- Scan logs (platform-wide) ---

@router.get("/scan-logs")
def list_all_scans(admin: AdminUser, db: DbSession, page: int = Query(default=1, ge=1), page_size: int = Query(default=20, le=100)):
    repo = ScanRepository(db)
    scans, total = repo.list_all_admin(page=page, page_size=page_size)
    items = []
    for s in scans:
        owner = repo.db.get(User, s.owner_id)
        items.append(AdminScanLogItem(
            id=s.id, name=s.name, owner_email=owner.email if owner else "unknown",
            status=s.status.value, verdict=s.verdict.value, created_at=s.created_at.isoformat(),
        ))
    return {"items": items, "total": total, "page": page, "page_size": page_size,
            "total_pages": max(1, math.ceil(total / page_size))}


# --- Analytics ---

@router.get("/analytics", response_model=AdminAnalyticsOut)
def get_analytics(admin: AdminUser, db: DbSession):
    import datetime as _dt

    total_users = db.execute(select(func.count()).select_from(User)).scalar_one()
    active_users = db.execute(select(func.count()).select_from(User).where(User.is_active == True)).scalar_one()  # noqa: E712
    total_scans = db.execute(select(func.count()).select_from(Scan)).scalar_one()

    today = _dt.datetime.now(_dt.timezone.utc).date()
    scans_today = db.execute(
        select(func.count()).select_from(Scan).where(func.date(Scan.created_at) == str(today))
    ).scalar_one()

    secure_count = db.execute(select(func.count()).select_from(Scan).where(Scan.verdict == Verdict.SECURE)).scalar_one()
    completed_count = db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.COMPLETED)
    ).scalar_one()
    overall_secure_rate = round((secure_count / completed_count) * 100, 1) if completed_count else 0.0

    total_vulns = db.execute(select(func.count()).select_from(Vulnerability)).scalar_one()

    sev_rows = db.execute(select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)).all()
    severity_distribution = [{"severity": sev.value, "count": count} for sev, count in sev_rows]

    engine_rows = db.execute(
        select(EngineResult.engine_name, func.count(), func.avg(EngineResult.duration_ms))
        .group_by(EngineResult.engine_name)
    ).all()
    engine_usage = [
        {"engine": name, "scans_run": count, "avg_duration_ms": round(avg_dur or 0, 0)}
        for name, count, avg_dur in engine_rows
    ]

    cwe_rows = db.execute(
        select(Vulnerability.cwe_id, func.count())
        .where(Vulnerability.cwe_id != "")
        .group_by(Vulnerability.cwe_id)
        .order_by(func.count().desc())
        .limit(8)
    ).all()
    top_cwe = [{"cwe_id": cwe, "count": count} for cwe, count in cwe_rows]

    return AdminAnalyticsOut(
        total_users=total_users, active_users=active_users, total_scans=total_scans, scans_today=scans_today,
        overall_secure_rate=overall_secure_rate, total_vulnerabilities=total_vulns,
        severity_distribution=severity_distribution, engine_usage=engine_usage, top_cwe_categories=top_cwe,
    )


# --- System monitoring ---

@router.get("/system-health", response_model=SystemHealthOut)
def get_system_health(admin: AdminUser, db: DbSession):
    import shutil as _shutil

    total_users = db.execute(select(func.count()).select_from(User)).scalar_one()
    total_scans = db.execute(select(func.count()).select_from(Scan)).scalar_one()

    upload_dir = Path(settings.UPLOAD_DIR)
    storage_bytes = sum(f.stat().st_size for f in upload_dir.rglob("*") if f.is_file()) if upload_dir.exists() else 0

    codeql_status = "available" if (_shutil.which(settings.CODEQL_CLI_PATH) or Path(settings.CODEQL_CLI_PATH).is_file()) else "fallback-mode"
    ai_status = "configured" if settings.ANTHROPIC_API_KEY else "not-configured"
    ml_status = "ready" if Path(settings.ML_MODEL_PATH).exists() else "will-auto-train"

    return SystemHealthOut(
        api_status="operational",
        database_status="operational",
        codeql_engine_status=codeql_status,
        ai_engine_status=ai_status,
        ml_engine_status=ml_status,
        uptime_seconds=round(time.monotonic() - _PROCESS_START, 1),
        total_users=total_users,
        total_scans=total_scans,
        storage_used_mb=round(storage_bytes / (1024 * 1024), 2),
    )
