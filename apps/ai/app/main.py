"""DSRclone AI service — model-facing copilot services (Prompt 21).

Responsibilities: finding explanation, remediation drafting,
executive/technical summaries and risk interpretation over NORMALIZED
findings, via the copilot pipeline (context → redaction → grounding).
It must never autonomously launch intrusive exploitation, execute
commands or run scanners (§7/§120). A live LLM is connected when the
deployment configures one (AI_LLM_* env); the status endpoints report
the real state — NOT_CONFIGURED when none is, never a fake success.
"""
from fastapi import FastAPI
from pydantic import BaseModel

from .config import settings
from .copilot import build_prompt, copilot_status, get_provider, llm_connected, redact_for_ai
from .logging_config import get_logger

logger = get_logger()
app = FastAPI(title="DSRclone AI Service", version="0.1.0")


@app.get("/")
async def root() -> dict:
    """Root info route: the bare service URL returns a small descriptor
    pointing at the real endpoints instead of a bare 404."""
    return {"service": "dsrclone-ai", "status": "ok", "health": "/health"}


@app.on_event("startup")
async def on_startup() -> None:
    logger.info("ai service starting", extra={})


@app.get("/health")
@app.head("/health")
async def health() -> dict:
    """Health endpoint: GET /health (HEAD supported for uptime probes)"""
    status = copilot_status()
    return {
        "status": "ok",
        "service": settings.service_name,
        "environment": settings.environment,
        "llm_connected": status["llm_connected"],
        "detail": status["detail"],
    }


class GenerateRequest(BaseModel):
    task: str
    context: str = ""
    evidence: str = ""
    question: str = ""


@app.post("/copilot/generate")
async def generate(req: GenerateRequest) -> dict:
    """Run the copilot pipeline: redact secrets from the context and
    evidence, assemble the separated prompt, and answer via the live
    provider when one is connected (the deterministic MOCK provider
    otherwise). Analysis only — no execution authority (§7/§120)."""
    safe_context, ctx_redactions = redact_for_ai(req.context)
    safe_evidence, ev_redactions = redact_for_ai(req.evidence)
    prompt = build_prompt(req.task, safe_context, safe_evidence, req.question)
    provider = get_provider()
    result = provider.generate(prompt, model=settings.llm_model)
    return {
        "text": result.text,
        "provider": provider.type,
        "model": settings.llm_model if provider.type != "MOCK" else "mock-1",
        "llm_connected": llm_connected(),
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
        "redactions": ctx_redactions + ev_redactions,
    }


@app.get("/copilot/status")
async def copilot() -> dict:
    """Copilot provider status (Prompt 21 §103/§110): identifiers and
    status only — never credentials."""
    return copilot_status()
