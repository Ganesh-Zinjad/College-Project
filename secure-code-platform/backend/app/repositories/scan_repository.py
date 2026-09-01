"""
Scan repository.

Encapsulates all direct ORM/session access for Scan, ScanFile, EngineResult,
Vulnerability and ScanLog. The scan lifecycle touches many tables at once,
so centralizing the queries here keeps `ScanService` focused on
orchestration logic rather than SQL.
"""
from datetime import datetime, timezone
from typing import Optional, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.scan import EngineResult, Scan, ScanFile, ScanLog, ScanStatus, Verdict
from app.models.vulnerability import Severity, Vulnerability


class ScanRepository:
    def __init__(self, db: Session):
        self.db = db

    # --- Scan ---

    def create_scan(self, *, owner_id: str, name: str) -> Scan:
        scan = Scan(owner_id=owner_id, name=name)
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        return self.db.get(Scan, scan_id)

    def get_scan_full(self, scan_id: str) -> Optional[Scan]:
        """Eager-loads everything needed to render the results page in one query."""
        stmt = (
            select(Scan)
            .where(Scan.id == scan_id)
            .options(
                selectinload(Scan.engine_results),
                selectinload(Scan.vulnerabilities),
                selectinload(Scan.files),
                selectinload(Scan.logs),
            )
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def save(self, scan: Scan) -> Scan:
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def delete(self, scan: Scan) -> None:
        self.db.delete(scan)
        self.db.commit()

    def list_for_owner(
        self,
        owner_id: str,
        *,
        search: str = "",
        status: str | None = None,
        verdict: str | None = None,
        page: int = 1,
        page_size: int = 10,
    ) -> tuple[Sequence[Scan], int]:
        stmt = select(Scan).where(Scan.owner_id == owner_id)
        if search:
            stmt = stmt.where(func.lower(Scan.name).like(f"%{search.lower()}%"))
        if status:
            stmt = stmt.where(Scan.status == status)
        if verdict:
            stmt = stmt.where(Scan.verdict == verdict)

        total = self.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        stmt = stmt.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        items = self.db.execute(stmt).scalars().all()
        return items, total

    def list_all_admin(self, *, page: int = 1, page_size: int = 20) -> tuple[Sequence[Scan], int]:
        stmt = select(Scan)
        total = self.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        stmt = stmt.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        items = self.db.execute(stmt).scalars().all()
        return items, total

    # --- Aggregate stats (dashboard / admin analytics) ---

    def count_for_owner(self, owner_id: str) -> int:
        return self.db.execute(select(func.count()).select_from(Scan).where(Scan.owner_id == owner_id)).scalar_one()

    def count_by_verdict(self, owner_id: str, verdict: Verdict) -> int:
        stmt = select(func.count()).select_from(Scan).where(Scan.owner_id == owner_id, Scan.verdict == verdict)
        return self.db.execute(stmt).scalar_one()

    def average_security_score(self, owner_id: str) -> float:
        stmt = select(func.avg(Scan.security_score)).where(
            Scan.owner_id == owner_id, Scan.status == ScanStatus.COMPLETED
        )
        result = self.db.execute(stmt).scalar_one()
        return round(result, 1) if result else 0.0

    def recent_for_owner(self, owner_id: str, limit: int = 5) -> Sequence[Scan]:
        stmt = (
            select(Scan)
            .where(Scan.owner_id == owner_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
        return self.db.execute(stmt).scalars().all()

    def scans_per_day(self, owner_id: str, days: int = 14) -> Sequence[Scan]:
        stmt = select(Scan).where(Scan.owner_id == owner_id).order_by(Scan.created_at.asc())
        return self.db.execute(stmt).scalars().all()

    # --- ScanFile ---

    def add_file(self, scan_file: ScanFile) -> ScanFile:
        self.db.add(scan_file)
        self.db.commit()
        self.db.refresh(scan_file)
        return scan_file

    def add_files(self, scan_files: list[ScanFile]) -> None:
        self.db.add_all(scan_files)
        self.db.commit()

    # --- EngineResult ---

    def add_engine_result(self, result: EngineResult) -> EngineResult:
        self.db.add(result)
        self.db.commit()
        self.db.refresh(result)
        return result

    # --- Vulnerability ---

    def add_vulnerabilities(self, vulns: list[Vulnerability]) -> None:
        if vulns:
            self.db.add_all(vulns)
            self.db.commit()

    def severity_breakdown(self, scan_id: str) -> dict:
        stmt = (
            select(Vulnerability.severity, func.count())
            .where(Vulnerability.scan_id == scan_id)
            .group_by(Vulnerability.severity)
        )
        rows = self.db.execute(stmt).all()
        breakdown = {s.value: 0 for s in Severity}
        for severity, count in rows:
            breakdown[severity.value] = count
        return breakdown

    def vulnerability_count(self, scan_id: str) -> int:
        stmt = select(func.count()).select_from(Vulnerability).where(Vulnerability.scan_id == scan_id)
        return self.db.execute(stmt).scalar_one()

    def org_severity_distribution(self, owner_id: str) -> list[dict]:
        stmt = (
            select(Vulnerability.severity, func.count())
            .join(Scan, Scan.id == Vulnerability.scan_id)
            .where(Scan.owner_id == owner_id)
            .group_by(Vulnerability.severity)
        )
        rows = self.db.execute(stmt).all()
        return [{"severity": sev.value, "count": count} for sev, count in rows]

    def critical_vulnerability_count(self, owner_id: str) -> int:
        stmt = (
            select(func.count())
            .select_from(Vulnerability)
            .join(Scan, Scan.id == Vulnerability.scan_id)
            .where(Scan.owner_id == owner_id, Vulnerability.severity == Severity.CRITICAL)
        )
        return self.db.execute(stmt).scalar_one()

    def total_vulnerabilities_for_owner(self, owner_id: str) -> int:
        stmt = (
            select(func.count())
            .select_from(Vulnerability)
            .join(Scan, Scan.id == Vulnerability.scan_id)
            .where(Scan.owner_id == owner_id)
        )
        return self.db.execute(stmt).scalar_one()

    # --- ScanLog ---

    def add_log(self, log: ScanLog) -> ScanLog:
        self.db.add(log)
        self.db.commit()
        self.db.refresh(log)
        return log

    def get_logs(self, scan_id: str) -> Sequence[ScanLog]:
        stmt = select(ScanLog).where(ScanLog.scan_id == scan_id).order_by(ScanLog.created_at.asc())
        return self.db.execute(stmt).scalars().all()
