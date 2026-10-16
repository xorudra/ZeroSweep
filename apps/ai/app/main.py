"""DSRclone AI service — model-facing copilot services (Prompt 21).

Responsibilities: finding explanation, remediation drafting,
executive/technical summaries and risk interpretation over NORMALIZED
findings, via the copilot pipeline (context → redaction → grounding).
It must never autonomously launch intrusive exploitation, execute
commands or run scanners (§7/§120). A live LLM is connected when the
deployment configures one (AI_LLM_* env); the status endpoints report
the real state — NOT_CONFIGURED when none is, never a fake success.
"""
import secrets
import time

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

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
    # Field caps: an unbounded context is unbounded provider spend.
    task: str = Field(max_length=2_000)
    context: str = Field(default="", max_length=20_000)
    evidence: str = Field(default="", max_length=20_000)
    question: str = Field(default="", max_length=2_000)


# Per-IP sliding-window cap for the generation endpoint. The endpoint
# spends live provider quota, so a hard cap — not a budget alert that
# only notifies — is the control.
_GEN_WINDOW_S = 60.0
_GEN_LIMIT = 30
_gen_hits: dict[str, list[float]] = {}


def _client_ip(request: Request) -> str:
    # Behind a proxy the LAST X-Forwarded-For entry is the hop the edge
    # actually observed; the first is client-supplied and spoofable.
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _rate_limited(ip: str) -> bool:
    now = time.monotonic()
    hits = [t for t in _gen_hits.get(ip, []) if now - t < _GEN_WINDOW_S]
    if len(hits) >= _GEN_LIMIT:
        _gen_hits[ip] = hits
        return True
    hits.append(now)
    _gen_hits[ip] = hits
    return False


@app.post("/copilot/generate")
async def generate(req: GenerateRequest, request: Request, x_service_key: str | None = Header(default=None)) -> dict:
    # The endpoint is reachable on the public internet wherever the
    # service is hosted, and it spends live provider quota: when a
    # service key is configured it is required, no exceptions; when
    # none is configured the endpoint fails closed outside
    # development/test (an unset key is local development only).
    if not settings.service_key:
        if settings.environment not in ("development", "test"):
            raise HTTPException(status_code=503, detail="service key not configured")
    elif not x_service_key or not secrets.compare_digest(x_service_key, settings.service_key):
        raise HTTPException(status_code=401, detail="service key required")
    if _rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="generation rate limit exceeded")
    """Run the copilot pipeline: redact secrets from the context and
    evidence, assemble the separated prompt, and answer via the live
    provider when one is connected (the deterministic MOCK provider
    otherwise). Analysis only — no execution authority (§7/§120)."""
    safe_task, task_redactions = redact_for_ai(req.task)
    safe_context, ctx_redactions = redact_for_ai(req.context)
    safe_evidence, ev_redactions = redact_for_ai(req.evidence)
    safe_question, q_redactions = redact_for_ai(req.question)
    prompt = build_prompt(safe_task, safe_context, safe_evidence, safe_question)
    provider = get_provider()
    result = provider.generate(prompt, model=settings.llm_model)
    return {
        "text": result.text,
        "provider": provider.type,
        "model": settings.llm_model if provider.type != "MOCK" else "mock-1",
        "llm_connected": llm_connected(),
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
        "redactions": task_redactions + ctx_redactions + ev_redactions + q_redactions,
    }


@app.get("/copilot/status")
async def copilot() -> dict:
    """Copilot provider status (Prompt 21 §103/§110): identifiers and
    status only — never credentials."""
    return copilot_status()
