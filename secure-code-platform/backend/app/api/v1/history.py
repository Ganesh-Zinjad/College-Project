"""History endpoints: search/filter/paginate past scans, delete, and re-run."""
import math

from fastapi import APIRouter, BackgroundTasks, Query

from app.core.dependencies import CurrentUser, DbSession
from app.core.exceptions import ForbiddenError, NotFoundError, ValidationFailedError
from app.models.scan import ScanStatus
from app.repositories.scan_repository import ScanRepository
from app.schemas.scan import PaginatedScanHistory, ScanHistoryItem, ScanStartResponse
from app.services.scan_service import ScanService

router = APIRouter(prefix="/history", tags=["History"])


@router.get("", response_model=PaginatedScanHistory)
def list_history(
    current_user: CurrentUser,
    db: DbSession,
    search: str = Query(default=""),
    status: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=100),
):
    repo = ScanRepository(db)
    scans, total = repo.list_for_owner(
        current_user.id, search=search, status=status, verdict=verdict, page=page, page_size=page_size
    )
    items = [
        ScanHistoryItem(
            id=s.id, name=s.name, status=s.status.value, verdict=s.verdict.value, scan_type=s.scan_type.value,
            security_score=s.security_score, total_files=s.total_files,
            vulnerability_count=repo.vulnerability_count(s.id),
            created_at=s.created_at, completed_at=s.completed_at,
        )
        for s in scans
    ]
    return PaginatedScanHistory(
        items=items, total=total, page=page, page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, current_user: CurrentUser, db: DbSession):
    repo = ScanRepository(db)
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    if scan.owner_id != current_user.id:
        raise ForbiddenError("This scan does not belong to you")

    from app.utils.file_utils import cleanup_scan_dir
    repo.delete(scan)
    cleanup_scan_dir(scan_id)
    return {"success": True, "message": "Scan deleted"}


@router.post("/{scan_id}/rerun", response_model=ScanStartResponse)
def rerun_scan(scan_id: str, current_user: CurrentUser, db: DbSession, background_tasks: BackgroundTasks):
    repo = ScanRepository(db)
    original = repo.get_scan_full(scan_id)
    if original is None:
        raise NotFoundError("Scan not found")
    if original.owner_id != current_user.id:
        raise ForbiddenError("This scan does not belong to you")
    if original.status == ScanStatus.RUNNING:
        raise ValidationFailedError("This scan is currently running")

    service = ScanService(repo)
    new_scan = service.create_scan_with_files(
        current_user.id,
        name=f"{original.name} (re-run)",
        file_metas=[
            {
                "filename": f.filename, "relative_path": f.relative_path, "stored_path": f.stored_path,
                "language": f.language, "size_bytes": f.size_bytes, "line_count": f.line_count,
            }
            for f in original.files
        ],
    )
    new_scan = service.configure_scan(
        new_scan.id, current_user.id,
        name=new_scan.name, scan_type=original.scan_type.value,
        engine_codeql_enabled=original.engine_codeql_enabled,
        engine_ai_enabled=original.engine_ai_enabled,
        engine_ml_enabled=original.engine_ml_enabled,
        target_cwe_ids=original.target_cwe_ids,
    )
    background_tasks.add_task(ScanService.execute_scan, new_scan.id)
    return ScanStartResponse(scan_id=new_scan.id, status="queued", message="Re-run started")
