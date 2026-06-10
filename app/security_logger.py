"""JSON security logging helpers."""

from __future__ import annotations

import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

from .config import get_settings


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        security_event = getattr(record, "security_event", None)
        if security_event:
            payload["security_event"] = security_event
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


def get_security_logger() -> logging.Logger:
    settings = get_settings()
    logger = logging.getLogger("llm_security_lab")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(getattr(logging, settings.security_log_level.upper(), logging.INFO))
    return logger


def new_request_id() -> str:
    return str(uuid.uuid4())


def log_security_event(
    event_type: str,
    severity: str,
    message: str,
    *,
    request_id: str | None = None,
    endpoint: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    event = {
        "event_type": event_type,
        "severity": severity,
        "request_id": request_id,
        "endpoint": endpoint,
        "metadata": metadata or {},
    }
    get_security_logger().info(message, extra={"security_event": event})
