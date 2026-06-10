"""OpenAI-compatible client for LM Studio."""

from __future__ import annotations

from typing import Any

from .config import get_settings

try:
    from openai import APIConnectionError, APIError, APITimeoutError, OpenAI
except ImportError:  # pragma: no cover - exercised only before dependencies are installed.
    APIConnectionError = None
    APIError = None
    APITimeoutError = None
    OpenAI = None


def call_llm(
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    max_tokens: int = 700,
) -> dict[str, Any]:
    settings = get_settings()
    if OpenAI is None:
        return {
            "ok": False,
            "content": "OpenAI Python SDK is not installed. Run: pip install -r requirements.txt",
            "error_type": "MissingDependency",
        }

    client = OpenAI(
        base_url=settings.lm_studio_base_url,
        api_key=settings.lm_studio_api_key,
        timeout=settings.llm_timeout_seconds,
    )

    try:
        response = client.chat.completions.create(
            model=settings.lm_studio_model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        content = response.choices[0].message.content or ""
        return {"ok": True, "content": content, "model": settings.lm_studio_model}
    except tuple(error for error in (APIConnectionError, APITimeoutError) if error is not None) as exc:
        return {
            "ok": False,
            "content": (
                "LM Studio local API is not reachable at "
                f"{settings.lm_studio_base_url}. Start the LM Studio server and confirm it is "
                "listening on localhost:1234."
            ),
            "error_type": exc.__class__.__name__,
        }
    except APIError as exc:
        return {
            "ok": False,
            "content": f"LM Studio API returned an error: {exc}",
            "error_type": exc.__class__.__name__,
        }
    except Exception as exc:  # Defensive boundary for local model/server failures.
        return {
            "ok": False,
            "content": f"Unexpected local LLM client error: {exc}",
            "error_type": exc.__class__.__name__,
        }
