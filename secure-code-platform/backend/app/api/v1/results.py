"""
Results endpoints — scan results, report exports, and Feature 2: AI explanation.

GET  /results/{scan_id}                       — full results for the results page
GET  /results/{scan_id}/export/{format}       — PDF / JSON / HTML download
POST /results/{scan_id}/explain/{vuln_id}     — Feature 2: deep AI explanation
"""
import math
from fastapi import APIRouter
from fastapi.responses import StreamingResponse, JSONResponse
import io

from app.core.dependencies import CurrentUser, DbSession
from app.core.exceptions import ForbiddenError, NotFoundError
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability
from app.repositories.scan_repository import ScanRepository
from app.schemas.scan import ExplainVulnerabilityResponse, ScanResultOut
from app.services.ai_explain_service import AIExplainService
from app.services.report_service import ReportService

router = APIRouter(prefix="/results", tags=["Results"])


def _get_completed_scan(scan_id: str, owner_id: str, db) -> Scan:
    repo = ScanRepository(db)
    scan = repo.get_scan_full(scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    if scan.owner_id != owner_id:
        raise ForbiddenError("This scan does not belong to you")
    return scan


@router.get("/{scan_id}", response_model=ScanResultOut)
def get_results(scan_id: str, current_user: CurrentUser, db: DbSession):
    repo = ScanRepository(db)
    scan = _get_completed_scan(scan_id, current_user.id, db)

    severity_breakdown = repo.severity_breakdown(scan_id)

    vuln_count = len(scan.vulnerabilities)

    return ScanResultOut(
        scan_id=scan.id,
        name=scan.name,
        status=scan.status.value,
        verdict=scan.verdict.value,
        scan_type=scan.scan_type.value,
        security_score=scan.security_score,
        risk_score=scan.risk_score,
        total_files=scan.total_files,
        total_lines=scan.total_lines,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        engine_results=scan.engine_results,
        vulnerabilities=scan.vulnerabilities,
        severity_breakdown=severity_breakdown,
    )


@router.get("/{scan_id}/export/{fmt}")
def export_report(scan_id: str, fmt: str, current_user: CurrentUser, db: DbSession):
    if fmt not in ("pdf", "json", "html"):
        raise NotFoundError("Unsupported export format. Choose: pdf, json, html")

    scan = _get_completed_scan(scan_id, current_user.id, db)
    safe_name = scan.name.replace(" ", "_").replace("/", "-")[:50]

    if fmt == "json":
        content = ReportService.to_json(scan)
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan-report-{safe_name}.json"'},
        )
    elif fmt == "html":
        content = ReportService.to_html(scan)
        return StreamingResponse(
            io.BytesIO(content),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="scan-report-{safe_name}.html"'},
        )
    else:  # pdf
        content = ReportService.to_pdf(scan)
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="scan-report-{safe_name}.pdf"'},
        )


# ---------------------------------------------------------------------------
# Feature 2 — Explainable AI
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/explain/{vuln_id}", response_model=ExplainVulnerabilityResponse)
def explain_vulnerability(scan_id: str, vuln_id: str, current_user: CurrentUser, db: DbSession):
    """
    Ask Claude for a deep, structured explanation of a single vulnerability:
    root cause, attack scenario, business impact, fix walkthrough,
    prevention tips, and related issues to watch for.

    Requires ANTHROPIC_API_KEY to be set in .env.
    Returns a structured JSON response the frontend renders into cards.
    """
    # Ownership check
    scan = _get_completed_scan(scan_id, current_user.id, db)

    # Find the specific vulnerability
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None or vuln.scan_id != scan_id:
        raise NotFoundError("Vulnerability not found in this scan")

    try:
        explanation = AIExplainService().explain(vuln)
    except RuntimeError as exc:
        # Missing API key or SDK — return a structured error the frontend can display
        return JSONResponse(
            status_code=503,
            content={
                "success": False,
                "error": {
                    "message": str(exc),
                    "type": "AIExplainUnavailable",
                }
            },
        )

    return ExplainVulnerabilityResponse(
        vuln_id=vuln_id,
        title=vuln.title,
        root_cause=explanation["root_cause"],
        attack_scenario=explanation["attack_scenario"],
        business_impact=explanation["business_impact"],
        fix_walkthrough=explanation["fix_walkthrough"],
        prevention_tips=explanation["prevention_tips"],
        related_vulnerabilities=explanation["related_vulnerabilities"],
        confidence_explanation=explanation["confidence_explanation"],
    )
