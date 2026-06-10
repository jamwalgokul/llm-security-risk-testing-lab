"""Least-privilege policy for simulated tool calls."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from .fake_tools import CURRENT_USER_ID


class ToolRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolPolicyDecision(BaseModel):
    allowed: bool
    requires_human_approval: bool = False
    requires_confirmation: bool = False
    reason: str
    tool_request: ToolRequest | None = None


def infer_tool_request(text: str) -> ToolRequest | None:
    lowered = text.lower()
    if "search_policy" in lowered or ("policy" in lowered and not _contains_refund_action(lowered)):
        return ToolRequest(tool_name="search_policy", arguments={"query": text[:250]})
    if "refund_order" in lowered or "refund" in lowered:
        amount = _extract_amount(text) or 0
        order_id = _extract_order_id(text) or "ORDER-DEMO"
        return ToolRequest(tool_name="refund_order", arguments={"order_id": order_id, "amount": amount})
    if "send_email" in lowered or "send an email" in lowered or "email" in lowered:
        to = _extract_email(text) or "recipient@example.local"
        return ToolRequest(
            tool_name="send_email",
            arguments={"to": to, "subject": "Demo message", "body": "Simulated body from lab request."},
        )
    if "get_user_profile" in lowered or "user profile" in lowered or "profile" in lowered:
        user_id = _extract_user_id(text) or CURRENT_USER_ID
        return ToolRequest(tool_name="get_user_profile", arguments={"user_id": user_id})
    return None


def authorize_tool_call(
    tool_request: ToolRequest | None,
    *,
    current_user_id: str = CURRENT_USER_ID,
    human_approved: bool = False,
    confirmed: bool = False,
) -> ToolPolicyDecision:
    if tool_request is None:
        return ToolPolicyDecision(allowed=True, reason="No simulated tool call requested.")

    tool_name = tool_request.tool_name
    args = tool_request.arguments

    if tool_name == "search_policy":
        return ToolPolicyDecision(allowed=True, reason="search_policy is read-only.", tool_request=tool_request)

    if tool_name == "get_user_profile":
        requested_user = str(args.get("user_id", ""))
        if requested_user != current_user_id:
            return ToolPolicyDecision(
                allowed=False,
                reason="get_user_profile is limited to the current authenticated user.",
                tool_request=tool_request,
            )
        return ToolPolicyDecision(allowed=True, reason="Current user profile access allowed.", tool_request=tool_request)

    if tool_name == "refund_order":
        amount = float(args.get("amount", 0))
        if amount <= 0 or str(args.get("order_id", "")) == "ORDER-DEMO":
            return ToolPolicyDecision(
                allowed=False,
                reason="Refund requests require an explicit order ID and positive amount.",
                tool_request=tool_request,
            )
        if amount > 5000 and not human_approved:
            return ToolPolicyDecision(
                allowed=False,
                requires_human_approval=True,
                reason="Refunds above 5000 require human approval.",
                tool_request=tool_request,
            )
        return ToolPolicyDecision(allowed=True, reason="Refund is within policy or approved.", tool_request=tool_request)

    if tool_name == "send_email":
        if not confirmed:
            return ToolPolicyDecision(
                allowed=False,
                requires_confirmation=True,
                reason="send_email requires explicit confirmation.",
                tool_request=tool_request,
            )
        return ToolPolicyDecision(allowed=True, reason="Email confirmation supplied.", tool_request=tool_request)

    return ToolPolicyDecision(allowed=False, reason="Unknown tool is denied by default.", tool_request=tool_request)


def _extract_amount(text: str) -> float | None:
    patterns = [
        r"amount\s*[=:]?\s*\$?([0-9]+(?:\.[0-9]{1,2})?)",
        r"\$([0-9]+(?:\.[0-9]{1,2})?)",
        r"\b([0-9]{4,}(?:\.[0-9]{1,2})?)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return float(match.group(1))
    return None


def _extract_order_id(text: str) -> str | None:
    match = re.search(r"order[_ -]?id\s*[=:]?\s*([A-Za-z0-9-]+)", text, flags=re.IGNORECASE)
    return match.group(1) if match else None


def _extract_email(text: str) -> str | None:
    match = re.search(r"[\w.\-+]+@[\w.\-]+\.[A-Za-z]{2,}", text)
    return match.group(0) if match else None


def _extract_user_id(text: str) -> str | None:
    match = re.search(r"user[_ -]?id\s*[=:]?\s*([A-Za-z0-9-]+)", text, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"\buser-[0-9]+\b", text, flags=re.IGNORECASE)
    return match.group(0) if match else None


def _contains_refund_action(lowered: str) -> bool:
    action_terms = [
        "refund_order",
        "refund order",
        "order_id",
        "issue",
        "process",
        "execute",
        "approve",
        "largest allowed refund",
        "self-approve",
    ]
    return "refund" in lowered and any(term in lowered for term in action_terms)
