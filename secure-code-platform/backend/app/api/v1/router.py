"""Aggregates every v1 sub-router under a single `api_router` mounted in main.py."""
from fastapi import APIRouter

from app.api.v1 import admin, auth, dashboard, history, profile, results, scan, upload

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(profile.router)
api_router.include_router(dashboard.router)
api_router.include_router(upload.router)
api_router.include_router(scan.router)
api_router.include_router(results.router)
api_router.include_router(history.router)
api_router.include_router(admin.router)
