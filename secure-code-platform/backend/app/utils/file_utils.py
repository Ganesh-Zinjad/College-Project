"""File-handling utilities shared by the upload and scan services."""
import shutil
import uuid
import zipfile
from pathlib import Path

from app.core.config import settings
from app.core.exceptions import FileTooLargeError
from app.utils.cwe_mapping import detect_language

# ---------------------------------------------------------------------------
# File classification — Feature 1: auto-filter unsupported files
# ---------------------------------------------------------------------------

# Extensions we can meaningfully scan for security vulnerabilities.
# Any file NOT in this set is skipped automatically with a user-facing notice.
SCANNABLE_EXTENSIONS: set[str] = {
    ".py",   # Python
    ".js",   # JavaScript
    ".jsx",  # React JSX
    ".ts",   # TypeScript
    ".tsx",  # React TSX
    ".java", # Java
    ".go",   # Go
    ".rb",   # Ruby
    ".php",  # PHP
    ".c",    # C
    ".cpp",  # C++
    ".cc",   # C++ (alternate)
    ".cxx",  # C++ (alternate)
    ".cs",   # C#
    ".sql",  # SQL — can contain injection-prone queries
    ".sh",   # Shell scripts — command injection risk
    ".bash", # Bash scripts
    ".ps1",  # PowerShell — command injection risk
    ".kt",   # Kotlin
    ".swift",# Swift
    ".rs",   # Rust
    ".scala",# Scala
    ".pl",   # Perl
    ".lua",  # Lua
    ".r",    # R
}

# Extensions that are definitively NOT scannable — shown in the "skipped" list.
# Anything not in SCANNABLE_EXTENSIONS (and not a zip) is also skipped, but
# these are the most common ones people accidentally include.
UNSCANNABLE_EXTENSIONS: set[str] = {
    # Markup / styling (no executable logic to audit)
    ".html", ".htm", ".xhtml", ".css", ".scss", ".sass", ".less",
    # Data / config files
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".lock", ".properties",
    # Documentation
    ".md", ".txt", ".rst", ".pdf", ".docx", ".doc", ".rtf",
    # Images / media
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp4", ".mov", ".avi", ".mp3", ".wav",
    # Compiled / binary artefacts (can't be statically read as source)
    ".class", ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib",
    ".jar", ".war", ".ear", ".whl",
    # Misc
    ".log", ".csv", ".tsv", ".gitignore", ".gitattributes", ".editorconfig",
    ".babelrc", ".eslintrc", ".prettierrc", ".npmrc", ".yarnrc",
}

# Directories that are never useful to scan (bloat inside zips)
_SKIP_DIR_NAMES: set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".idea", ".vscode", "coverage", ".pytest_cache",
    ".mypy_cache", "target", "out", "bin", "obj",
}


def is_scannable(filename: str) -> bool:
    """Return True if the file extension is one we can audit for vulnerabilities."""
    suffix = Path(filename).suffix.lower()
    if not suffix:
        return False  # no extension — can't classify, skip
    return suffix in SCANNABLE_EXTENSIONS


def skip_reason(filename: str) -> str:
    """Human-readable reason why a file was skipped."""
    suffix = Path(filename).suffix.lower()
    if not suffix:
        return "No file extension — cannot determine language"
    if suffix in UNSCANNABLE_EXTENSIONS:
        category_map = {
            **{e: "Markup/Styling (no executable logic to audit)" for e in {".html",".htm",".xhtml",".css",".scss",".sass",".less"}},
            **{e: "Data/Config file" for e in {".json",".xml",".yaml",".yml",".toml",".ini",".cfg",".conf",".env",".lock",".properties"}},
            **{e: "Documentation" for e in {".md",".txt",".rst",".pdf",".docx",".doc",".rtf"}},
            **{e: "Image/Media file" for e in {".png",".jpg",".jpeg",".gif",".svg",".ico",".webp",".mp4",".mov",".avi",".mp3",".wav"}},
            **{e: "Compiled/Binary artefact" for e in {".class",".pyc",".pyo",".exe",".dll",".so",".dylib",".jar",".war",".ear",".whl"}},
        }
        return category_map.get(suffix, f"Unsupported file type ({suffix})")
    return f"Extension '{suffix}' is not in the supported language list"


# ---------------------------------------------------------------------------
# Upload helpers
# ---------------------------------------------------------------------------

def validate_upload_size(filename: str, size_bytes: int) -> None:
    """Raise if the file exceeds the configured size limit."""
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if size_bytes > max_bytes:
        raise FileTooLargeError(f"'{filename}' exceeds the {settings.MAX_UPLOAD_SIZE_MB} MB upload limit")


def make_scan_upload_dir(scan_id: str) -> Path:
    upload_dir = Path(settings.UPLOAD_DIR) / scan_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


def save_single_file(scan_dir: Path, filename: str, content: bytes, relative_path: str | None = None) -> dict:
    relative_path = relative_path or filename
    dest = scan_dir / relative_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    return _file_metadata(dest, relative_path)


def extract_zip(scan_dir: Path, zip_bytes: bytes) -> tuple[list[dict], list[dict]]:
    """
    Extract an uploaded ZIP and return:
      (accepted_files, skipped_files)

    accepted_files — list of file metadata dicts for scannable source files.
    skipped_files  — list of {"filename", "reason"} for auto-filtered entries.
    """
    tmp_zip_path = scan_dir / f"_upload_{uuid.uuid4().hex}.zip"
    tmp_zip_path.write_bytes(zip_bytes)

    accepted: list[dict] = []
    skipped: list[dict] = []

    try:
        with zipfile.ZipFile(tmp_zip_path) as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue

                path_parts = Path(member.filename).parts

                # Skip hidden dirs / noise dirs
                if any(part in _SKIP_DIR_NAMES or part.startswith(".") for part in path_parts):
                    skipped.append({
                        "filename": member.filename,
                        "reason": f"Inside excluded directory ({next((p for p in path_parts if p in _SKIP_DIR_NAMES or p.startswith('.')), '.')})",
                    })
                    continue

                # Size check
                if member.file_size > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
                    skipped.append({
                        "filename": member.filename,
                        "reason": f"Exceeds {settings.MAX_UPLOAD_SIZE_MB} MB size limit",
                    })
                    continue

                # Scannability check — Feature 1
                if not is_scannable(member.filename):
                    skipped.append({
                        "filename": member.filename,
                        "reason": skip_reason(member.filename),
                    })
                    continue

                dest = scan_dir / member.filename
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)
                accepted.append(_file_metadata(dest, member.filename))
    finally:
        tmp_zip_path.unlink(missing_ok=True)

    return accepted, skipped


def _file_metadata(path: Path, relative_path: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        line_count = text.count("\n") + 1
    except OSError:
        line_count = 0

    return {
        "filename": path.name,
        "relative_path": relative_path.replace("\\", "/"),
        "stored_path": str(path),
        "language": detect_language(path.name),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "line_count": line_count,
    }


def cleanup_scan_dir(scan_id: str) -> None:
    upload_dir = Path(settings.UPLOAD_DIR) / scan_id
    shutil.rmtree(upload_dir, ignore_errors=True)
