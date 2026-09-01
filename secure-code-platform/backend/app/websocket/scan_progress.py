"""
WebSocket endpoint for live scan progress.

The scan-progress page connects to `/ws/scan/{scan_id}?token=<access_token>`
(a query param, since browsers can't set custom headers on a WebSocket
handshake) and receives a JSON message every time new log lines, progress,
or the final verdict become available. Polling (GET /scan/{id}/progress) is
still fully supported as a fallback for clients/networks that block
websockets — the frontend's `websocket.js` module falls back automatically.
"""
import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.database import db_session
from app.core.security import TokenError, TokenType, decode_token
from app.repositories.scan_repository import ScanRepository
from app.repositories.user_repository import UserRepository

router = APIRouter()

_POLL_INTERVAL_SECONDS = 1.0


@router.websocket("/ws/scan/{scan_id}")
async def scan_progress_socket(websocket: WebSocket, scan_id: str, token: str = ""):
    user = _authenticate(token)
    if user is None:
        await websocket.close(code=4401, reason="Unauthorized")
        return

    with db_session() as db:
        scan = ScanRepository(db).get_scan(scan_id)
        if scan is None or scan.owner_id != user.id:
            await websocket.close(code=4404, reason="Scan not found")
            return

    await websocket.accept()
    last_log_count = 0

    try:
        while True:
            with db_session() as db:
                repo = ScanRepository(db)
                scan = repo.get_scan(scan_id)
                if scan is None:
                    break
                logs = repo.get_logs(scan_id)

            new_logs = logs[last_log_count:]
            if new_logs:
                await websocket.send_text(json.dumps({
                    "type": "logs",
                    "logs": [
                        {"engine": l.engine_name, "level": l.level, "message": l.message,
                         "created_at": l.created_at.isoformat()}
                        for l in new_logs
                    ],
                }))
                last_log_count = len(logs)

            await websocket.send_text(json.dumps({
                "type": "status",
                "status": scan.status.value,
                "progress_percent": scan.progress_percent,
                "current_engine": scan.current_engine,
                "verdict": scan.verdict.value,
            }))

            if scan.status.value in {"completed", "failed", "cancelled"}:
                break

            await asyncio.sleep(_POLL_INTERVAL_SECONDS)

    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass  # already closed


def _authenticate(token: str):
    if not token:
        return None
    try:
        payload = decode_token(token, TokenType.ACCESS)
    except TokenError:
        return None
    with db_session() as db:
        return UserRepository(db).get_by_id(payload["sub"])
