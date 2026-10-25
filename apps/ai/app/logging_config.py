import json
import logging
import sys
from datetime import datetime, timezone

SENSITIVE = ("password", "secret", "token", "api_key", "authorization", "cookie", "credential")


class JsonFormatter(logging.Formatter):
    """Structured JSON logs with sensitive-key redaction."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "zerosweep-ai",
            "message": record.getMessage(),
        }
        return json.dumps(entry)


def get_logger(name: str = "zerosweep-ai") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
