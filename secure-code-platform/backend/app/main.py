"""
Application entry point.

Run with: uvicorn app.main:app --reload --port 8000
Interactive API docs: http://localhost:8000/docs
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import init_db
from app.core.exceptions import register_exception_handlers
from app.websocket.scan_progress import router as websocket_router

logging.basicConfig(
    level=logging.INFO if settings.DEBUG else logging.WARNING,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("secure_code_platform")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- startup ---
    init_db()
    Path(settings.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
    Path(settings.CODEQL_DB_DIR).mkdir(parents=True, exist_ok=True)
    Path(settings.ML_MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    logger.info("%s started in %s mode", settings.APP_NAME, settings.APP_ENV)
    yield
    # --- shutdown ---
    logger.info("Shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "REST API for the AI Secure Code Vulnerability Detection Platform — a triple-judge "
        "evaluation engine combining static analysis (CodeQL), an AI security auditor (Claude), "
        "and a machine-learning vulnerability classifier."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)
app.include_router(websocket_router)


@app.get("/", tags=["Health"])
def root():
    return {
        "service": settings.APP_NAME,
        "status": "operational",
        "docs": "/docs",
        "api_prefix": settings.API_V1_PREFIX,
    }


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "healthy"}
