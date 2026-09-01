"""
Scan configuration + execution endpoints.

POST /scan/configure persists the chosen engines/scan-type/CWE targets.
POST /scan/{id}/start kicks off execution as a FastAPI BackgroundTask so the
HTTP response returns immediately; the actual scan (which calls out to
CodeQL/Claude/the ML model and can take seconds to minutes) runs after the
response is sent. The frontend then polls GET /scan/{id}/progress (or
subscribes to the websocket in app/websocket) to render live logs.
"""
from fastapi import APIRouter, BackgroundTasks

from app.core.dependencies import CurrentUser, DbSession
from app.core.exceptions import ForbiddenError, NotFoundError, ValidationFailedError
from app.models.scan import ScanStatus
from app.repositories.scan_repository import ScanRepository
from app.schemas.scan import ScanConfigRequest, ScanLogOut, ScanProgressOut, ScanStartResponse
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scan", tags=["Scan"])


def _owned_scan(repo: ScanRepository, scan_id: str, owner_id: str):
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    if scan.owner_id != owner_id:
        raise ForbiddenError("This scan does not belong to you")
    return scan


@router.post("/configure", response_model=ScanStartResponse)
def configure_scan(payload: ScanConfigRequest, current_user: CurrentUser, db: DbSession):
    if not (payload.engine_codeql_enabled or payload.engine_ai_enabled or payload.engine_ml_enabled):
        raise ValidationFailedError("At least one engine must be enabled")

    repo = ScanRepository(db)
    service = ScanService(repo)
    scan = service.configure_scan(
        payload.scan_id, current_user.id,
        name=payload.name, scan_type=payload.scan_type,
        engine_codeql_enabled=payload.engine_codeql_enabled,
        engine_ai_enabled=payload.engine_ai_enabled,
        engine_ml_enabled=payload.engine_ml_enabled,
        target_cwe_ids=payload.target_cwe_ids,
    )
    return ScanStartResponse(scan_id=scan.id, status=scan.status.value, message="Scan configured")


@router.post("/{scan_id}/start", response_model=ScanStartResponse)
def start_scan(scan_id: str, current_user: CurrentUser, db: DbSession, background_tasks: BackgroundTasks):
    repo = ScanRepository(db)
    scan = _owned_scan(repo, scan_id, current_user.id)

    if scan.status == ScanStatus.RUNNING:
        raise ValidationFailedError("This scan is already running")

    background_tasks.add_task(ScanService.execute_scan, scan_id)
    return ScanStartResponse(scan_id=scan_id, status="queued", message="Scan started")


@router.post("/{scan_id}/cancel", response_model=ScanStartResponse)
def cancel_scan(scan_id: str, current_user: CurrentUser, db: DbSession):
    repo = ScanRepository(db)
    scan = _owned_scan(repo, scan_id, current_user.id)
    if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
        raise ValidationFailedError("This scan has already finished")
    scan.status = ScanStatus.CANCELLED
    repo.save(scan)
    return ScanStartResponse(scan_id=scan_id, status="cancelled", message="Scan cancelled")


@router.get("/{scan_id}/progress", response_model=ScanProgressOut)
def get_progress(scan_id: str, current_user: CurrentUser, db: DbSession):
    repo = ScanRepository(db)
    scan = _owned_scan(repo, scan_id, current_user.id)
    logs = repo.get_logs(scan_id)
    return ScanProgressOut(
        scan_id=scan.id,
        status=scan.status.value,
        progress_percent=scan.progress_percent,
        current_engine=scan.current_engine,
        verdict=scan.verdict.value,
        logs=[ScanLogOut.model_validate(log) for log in logs],
    )
