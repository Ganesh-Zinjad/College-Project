"""
Upload endpoints — Feature 1: auto-filter unsupported files.

Every uploaded file is checked with `is_scannable()` before being saved.
Files that cannot be audited for security vulnerabilities (HTML, CSS, images,
config files, etc.) are silently skipped and returned in `skipped_files` so
the UI can show the user exactly what was filtered out and why.

ZIP archives are extracted server-side; the same per-file filtering is
applied to every entry inside the archive.
"""
from fastapi import APIRouter, UploadFile

from app.core.dependencies import CurrentUser, DbSession
from app.core.exceptions import ValidationFailedError
from app.models.scan import ScanFile
from app.repositories.scan_repository import ScanRepository
from app.schemas.scan import SkippedFileOut, UploadResponse
from app.services.scan_service import ScanService
from app.utils.file_utils import (
    extract_zip,
    is_scannable,
    make_scan_upload_dir,
    save_single_file,
    skip_reason,
    validate_upload_size,
)

router = APIRouter(prefix="/upload", tags=["Upload"])


@router.post("", response_model=UploadResponse)
async def upload_files(files: list[UploadFile], current_user: CurrentUser, db: DbSession):
    if not files:
        raise ValidationFailedError("No files were provided")

    scan_service = ScanService(ScanRepository(db))
    scan = scan_service.create_scan_with_files(
        current_user.id, name=_default_scan_name(files), file_metas=[]
    )
    scan_dir = make_scan_upload_dir(scan.id)

    accepted_metas: list[dict] = []
    all_skipped: list[dict] = []

    for upload in files:
        content = await upload.read()

        # Size check (applies to all files including non-scannable ones)
        try:
            validate_upload_size(upload.filename, len(content))
        except Exception as exc:
            all_skipped.append({"filename": upload.filename, "reason": str(exc)})
            continue

        # ZIP: extract and filter internally
        if upload.filename.lower().endswith(".zip"):
            accepted, skipped = extract_zip(scan_dir, content)
            accepted_metas.extend(accepted)
            all_skipped.extend(skipped)
            continue

        # Feature 1 — non-scannable single file: record and skip
        if not is_scannable(upload.filename):
            all_skipped.append({
                "filename": upload.filename,
                "reason": skip_reason(upload.filename),
            })
            continue

        # Scannable single file: save it
        accepted_metas.append(
            save_single_file(scan_dir, upload.filename, content, relative_path=upload.filename)
        )

    # If everything was filtered out, abort early with a clear message.
    if not accepted_metas:
        skipped_summary = ", ".join(d["filename"] for d in all_skipped[:5])
        raise ValidationFailedError(
            f"No scannable source files were found. "
            f"The following were automatically removed: {skipped_summary}. "
            f"Supported languages: Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C/C++, C#, SQL, Shell scripts."
        )

    # Persist accepted files
    repo = ScanRepository(db)
    scan_obj = repo.get_scan(scan.id)
    scan_obj.name = _default_scan_name(files)
    repo.add_files([
        ScanFile(
            scan_id=scan.id,
            filename=m["filename"],
            relative_path=m["relative_path"],
            stored_path=m["stored_path"],
            language=m["language"],
            size_bytes=m["size_bytes"],
            line_count=m["line_count"],
        )
        for m in accepted_metas
    ])
    scan_obj.total_files = len(accepted_metas)
    scan_obj.total_lines = sum(m["line_count"] for m in accepted_metas)
    repo.save(scan_obj)

    return UploadResponse(
        scan_id=scan.id,
        files=[
            {
                "id": "",
                "filename": m["filename"],
                "relative_path": m["relative_path"],
                "language": m["language"],
                "size_bytes": m["size_bytes"],
                "line_count": m["line_count"],
            }
            for m in accepted_metas
        ],
        total_files=len(accepted_metas),
        total_lines=sum(m["line_count"] for m in accepted_metas),
        skipped_files=[SkippedFileOut(**s) for s in all_skipped],
        total_skipped=len(all_skipped),
    )


def _default_scan_name(files: list[UploadFile]) -> str:
    if len(files) == 1:
        return files[0].filename
    return f"{len(files)} files — {files[0].filename} and others"
