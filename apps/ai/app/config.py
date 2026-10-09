"""AI service configuration. This phase ships the service foundation only —
no LLM is connected yet. Later phases will consume NORMALIZED findings here
(explanations, triage assistance, summaries); the AI layer never launches tools."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    service_name: str = "dsrclone-ai"
    environment: str = os.environ.get("NODE_ENV", "development")
    host: str = os.environ.get("AI_HOST", "0.0.0.0")
    port: int = int(os.environ.get("AI_PORT", "8000"))
    log_level: str = os.environ.get("AI_LOG_LEVEL", "INFO")
    # Live LLM provider (wired 2026-10-09 at the owner's order): any
    # OpenAI-compatible chat-completions endpoint. An empty base URL or
    # API key leaves the service honestly NOT_CONFIGURED (mock only).
    llm_base_url: str = os.environ.get("AI_LLM_BASE_URL", "").rstrip("/")
    llm_api_key: str = os.environ.get("AI_LLM_API_KEY", "")
    llm_model: str = os.environ.get("AI_LLM_MODEL", "gemini-2.5-flash")
    llm_timeout_s: float = float(os.environ.get("AI_LLM_TIMEOUT_S", "30"))


settings = Settings()
