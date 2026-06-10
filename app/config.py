"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from functools import lru_cache

from pydantic import BaseModel, Field

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency is included, fallback keeps imports robust.
    load_dotenv = None

if load_dotenv:
    load_dotenv()


class AppSettings(BaseModel):
    app_name: str = "llm-security-risk-testing-lab"
    environment: str = Field(default="local", description="Runtime environment name")
    lm_studio_base_url: str = Field(default="http://localhost:1234/v1")
    lm_studio_api_key: str = Field(default="lm-studio")
    lm_studio_model: str = Field(default="deepseek-r1-distill-qwen-q4")
    llm_timeout_seconds: float = Field(default=45.0)
    max_input_chars: int = Field(default=8000)
    rate_limit_per_minute: int = Field(default=20)
    security_log_level: str = Field(default="INFO")

    @classmethod
    def from_env(cls) -> "AppSettings":
        return cls(
            environment=os.getenv("APP_ENV", "local"),
            lm_studio_base_url=os.getenv("LM_STUDIO_BASE_URL", "http://localhost:1234/v1"),
            lm_studio_api_key=os.getenv("LM_STUDIO_API_KEY", "lm-studio"),
            lm_studio_model=os.getenv("LM_STUDIO_MODEL", "deepseek-r1-distill-qwen-q4"),
            llm_timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "45")),
            max_input_chars=int(os.getenv("MAX_INPUT_CHARS", "8000")),
            rate_limit_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "20")),
            security_log_level=os.getenv("SECURITY_LOG_LEVEL", "INFO"),
        )


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings.from_env()
