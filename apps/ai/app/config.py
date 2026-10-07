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


settings = Settings()
