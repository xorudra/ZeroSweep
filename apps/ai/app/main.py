"""DSRclone AI service — foundation only.

Responsibilities in later phases: finding explanation, deduplication
assistance, remediation drafting, executive/technical summaries and risk
interpretation over NORMALIZED findings. It must never autonomously launch
intrusive exploitation, and no LLM is connected in this phase.
"""
from fastapi import FastAPI

from .config import settings
from .logging_config import get_logger

logger = get_logger()
app = FastAPI(title="DSRclone AI Service", version="0.1.0")


@app.on_event("startup")
async def on_startup() -> None:
    logger.info("ai service starting", extra={})


@app.get("/health")
async def health() -> dict:
    """Health endpoint: GET /health"""
    return {
        "status": "ok",
        "service": settings.service_name,
        "environment": settings.environment,
        "llm_connected": False,
        "detail": "Foundation only — no LLM connected yet (by design, this phase).",
    }
