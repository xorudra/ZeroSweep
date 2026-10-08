"""DSRclone AI service — model-facing copilot services (Prompt 21).

Responsibilities: finding explanation, remediation drafting,
executive/technical summaries and risk interpretation over NORMALIZED
findings, via the copilot pipeline (context → redaction → grounding).
It must never autonomously launch intrusive exploitation, execute
commands or run scanners (§7/§120). No live LLM is connected in this
build — the status endpoints report NOT_CONFIGURED honestly.
"""
from fastapi import FastAPI

from .config import settings
from .copilot import copilot_status
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
        "detail": "Copilot pipeline implemented (Prompt 21); no live LLM connected — NOT_CONFIGURED by design.",
    }


@app.get("/copilot/status")
async def copilot() -> dict:
    """Copilot provider status (Prompt 21 §103/§110): identifiers and
    status only — never credentials."""
    return copilot_status()
