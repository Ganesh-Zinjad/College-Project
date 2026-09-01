"""
Scan service.

Owns the full scan lifecycle: receiving uploaded files, starting a scan job,
running it (synchronously, off the request/response cycle via a background
task — see `api/v1/scan.py`), and persisting engine results + findings.

Each lifecycle step opens its own short-lived DB session via `db_session()`
rather than sharing the request's session, because the scan runs in a
background task that outlives the original request.
"""
import datetime as dt
from pathlib import Path

from app.core.database import db_session
from app.core.exceptions import ForbiddenError, NotFoundError
from app.models.scan import EngineResult, Scan, ScanFile, ScanLog, ScanStatus, ScanType, Verdict
from app.models.vulnerability import Vulnerability
from app.repositories.scan_repository import ScanRepository
from app.repositories.user_repository import UserRepository
from app.services.email_service import EmailService
from app.services.engines.verdict_engine import VerdictEngine


class ScanService:
    def __init__(self, scan_repo: ScanRepository):
        self.scan_repo = scan_repo

    # ------------------------------------------------------------------
    # Upload + configuration (runs inside the original request)
    # ------------------------------------------------------------------

    def create_scan_with_files(self, owner_id: str, name: str, file_metas: list[dict]) -> Scan:
        scan = self.scan_repo.create_scan(owner_id=owner_id, name=name)

        scan_files = [
            ScanFile(
                scan_id=scan.id,
                filename=meta["filename"],
                relative_path=meta["relative_path"],
                stored_path=meta["stored_path"],
                language=meta["language"],
                size_bytes=meta["size_bytes"],
                line_count=meta["line_count"],
            )
            for meta in file_metas
        ]
        self.scan_repo.add_files(scan_files)

        scan.total_files = len(file_metas)
        scan.total_lines = sum(m["line_count"] for m in file_metas)
        return self.scan_repo.save(scan)

    def configure_scan(
        self,
        scan_id: str,
        owner_id: str,
        *,
        name: str,
        scan_type: str,
        engine_codeql_enabled: bool,
        engine_ai_enabled: bool,
        engine_ml_enabled: bool,
        target_cwe_ids: str,
    ) -> Scan:
        scan = self._get_owned_scan(scan_id, owner_id)
        scan.name = name
        scan.scan_type = ScanType(scan_type)
        scan.engine_codeql_enabled = engine_codeql_enabled
        scan.engine_ai_enabled = engine_ai_enabled
        scan.engine_ml_enabled = engine_ml_enabled
        scan.target_cwe_ids = target_cwe_ids
        scan.status = ScanStatus.QUEUED
        return self.scan_repo.save(scan)

    def _get_owned_scan(self, scan_id: str, owner_id: str) -> Scan:
        scan = self.scan_repo.get_scan(scan_id)
        if scan is None:
            raise NotFoundError("Scan not found")
        if scan.owner_id != owner_id:
            raise ForbiddenError("This scan does not belong to you")
        return scan

    # ------------------------------------------------------------------
    # Execution (runs in a background task, after the HTTP response is sent)
    # ------------------------------------------------------------------

    @staticmethod
    def execute_scan(scan_id: str) -> None:
        """
        Entry point for the background task. Opens its own DB session because
        it runs after the original request's session has already closed.
        """
        with db_session() as db:
            repo = ScanRepository(db)
            scan = repo.get_scan(scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.RUNNING
            scan.started_at = dt.datetime.now(dt.timezone.utc)
            repo.save(scan)

        ScanService._log(scan_id, "system", "info", "Scan started")

        try:
            files = ScanService._collect_files(scan_id)
            target_cwe_ids = [c.strip() for c in ScanService._get_target_cwes(scan_id) if c.strip()]
            enabled = ScanService._get_enabled_engines(scan_id)

            def log_cb(level: str, message: str, engine: str = "system") -> None:
                ScanService._log(scan_id, engine, level, message)

            def on_engine_start(engine_key: str) -> None:
                progress_map = {"codeql": 10, "ai": 45, "ml": 75}
                ScanService._update_progress(scan_id, progress_map.get(engine_key, 50), engine_key)

            def on_engine_done(engine_key: str, result) -> None:
                with db_session() as db:
                    repo = ScanRepository(db)
                    repo.add_engine_result(EngineResult(
                        scan_id=scan_id,
                        engine_name=result.engine_name,
                        verdict=Verdict(result.verdict.value if result.verdict.value != "error" else "vulnerable"),
                        confidence=result.confidence,
                        findings_count=len(result.findings),
                        duration_ms=result.duration_ms,
                        summary=result.summary,
                        raw_output=result.raw_output,
                    ))
                    vulns = [
                        Vulnerability(
                            scan_id=scan_id,
                            source_engine=result.engine_name,
                            title=f.title,
                            description=f.description,
                            severity=f.severity,
                            risk_score=f.risk_score,
                            cwe_id=f.cwe_id,
                            cve_id=f.cve_id,
                            owasp_category=f.owasp_category,
                            file_path=f.file_path,
                            line_start=f.line_start,
                            line_end=f.line_end,
                            code_snippet=f.code_snippet,
                            suggested_fix=f.suggested_fix,
                            secure_code_example=f.secure_code_example,
                            confidence=f.confidence,
                        )
                        for f in result.findings
                    ]
                    repo.add_vulnerabilities(vulns)

            outcome = VerdictEngine().run_all(
                files=files,
                enabled_engines=enabled,
                target_cwe_ids=target_cwe_ids,
                log=lambda level, message: log_cb(level, message),
                on_engine_start=on_engine_start,
                on_engine_done=on_engine_done,
            )

            ScanService._finalize(scan_id, outcome)

        except Exception as exc:  # noqa: BLE001 — a scan must never crash the worker silently
            ScanService._fail(scan_id, str(exc))

    @staticmethod
    def _collect_files(scan_id: str) -> list[dict]:
        with db_session() as db:
            repo = ScanRepository(db)
            scan = repo.get_scan_full(scan_id)
            return [
                {"path": f.stored_path, "relative_path": f.relative_path, "language": f.language}
                for f in scan.files
                if Path(f.stored_path).is_file()
            ]

    @staticmethod
    def _get_target_cwes(scan_id: str) -> list[str]:
        with db_session() as db:
            scan = ScanRepository(db).get_scan(scan_id)
            return scan.target_cwe_ids.split(",") if scan and scan.target_cwe_ids else []

    @staticmethod
    def _get_enabled_engines(scan_id: str) -> dict[str, bool]:
        with db_session() as db:
            scan = ScanRepository(db).get_scan(scan_id)
            if scan is None:
                return {"codeql": True, "ai": True, "ml": True}
            return {
                "codeql": scan.engine_codeql_enabled,
                "ai": scan.engine_ai_enabled,
                "ml": scan.engine_ml_enabled,
            }

    @staticmethod
    def _log(scan_id: str, engine: str, level: str, message: str) -> None:
        with db_session() as db:
            ScanRepository(db).add_log(ScanLog(scan_id=scan_id, engine_name=engine, level=level, message=message))

    @staticmethod
    def _update_progress(scan_id: str, percent: int, current_engine: str) -> None:
        with db_session() as db:
            repo = ScanRepository(db)
            scan = repo.get_scan(scan_id)
            if scan:
                scan.progress_percent = percent
                scan.current_engine = current_engine
                repo.save(scan)

    @staticmethod
    def _finalize(scan_id: str, outcome) -> None:
        with db_session() as db:
            repo = ScanRepository(db)
            scan = repo.get_scan(scan_id)
            scan.status = ScanStatus.COMPLETED
            scan.verdict = Verdict(outcome.final_verdict)
            scan.security_score = outcome.security_score
            scan.risk_score = outcome.risk_score
            scan.progress_percent = 100
            scan.current_engine = ""
            scan.completed_at = dt.datetime.now(dt.timezone.utc)
            repo.save(scan)
            owner = UserRepository(db).get_by_id(scan.owner_id)
            owner_email = owner.email if owner else None
            owner_name = owner.full_name if owner else ""
            notify_complete = owner.notify_email_on_scan_complete if owner else False
            notify_critical = owner.notify_email_on_critical_vuln if owner else False

        ScanService._log(scan_id, "system", "success", f"Scan complete — verdict: {outcome.final_verdict.upper()}")

        # Notifications are best-effort — a delivery failure must never affect the scan's own success.
        try:
            if owner_email and notify_complete:
                EmailService().send_scan_complete_email(owner_email, owner_name, scan.name, outcome.final_verdict, scan_id)
            if owner_email and notify_critical:
                critical_count = sum(1 for r in outcome.engine_results for f in r.findings if f.severity == "critical")
                if critical_count:
                    EmailService().send_critical_vuln_email(owner_email, owner_name, scan.name, critical_count, scan_id)
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _fail(scan_id: str, error_message: str) -> None:
        with db_session() as db:
            repo = ScanRepository(db)
            scan = repo.get_scan(scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = error_message[:2000]
                repo.save(scan)
        ScanService._log(scan_id, "system", "error", f"Scan failed: {error_message}")
