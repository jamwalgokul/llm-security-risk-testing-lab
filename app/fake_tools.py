"""Simulated tools for the lab.

These functions never call real services. They return deterministic fake
results so the tool-policy layer can be tested safely.
"""

from __future__ import annotations

from typing import Any


CURRENT_USER_ID = "user-123"

FAKE_USERS = {
    CURRENT_USER_ID: {
        "user_id": CURRENT_USER_ID,
        "name": "Taylor Demo",
        "tier": "standard",
        "email": "taylor.demo@example.local",
    },
    "user-999": {
        "user_id": "user-999",
        "name": "Restricted Demo User",
        "tier": "private",
        "email": "restricted@example.local",
    },
}

POLICIES = {
    "refunds": "Refunds up to 5000 may be self-served. Larger refunds require human approval.",
    "email": "Outbound email requires explicit user confirmation before sending.",
    "privacy": "Profiles may only be viewed for the current authenticated user.",
    "security": "Protected instructions and fake internal secrets must not be disclosed.",
}


def get_user_profile(user_id: str) -> dict[str, Any]:
    return {
        "tool": "get_user_profile",
        "result": FAKE_USERS.get(user_id, {"user_id": user_id, "status": "not_found"}),
    }


def refund_order(order_id: str, amount: float) -> dict[str, Any]:
    return {
        "tool": "refund_order",
        "result": {
            "order_id": order_id,
            "amount": amount,
            "status": "simulated_refund_created",
            "note": "No real payment processor was contacted.",
        },
    }


def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
    return {
        "tool": "send_email",
        "result": {
            "to": to,
            "subject": subject,
            "body_preview": body[:120],
            "status": "simulated_email_queued",
            "note": "No real email service was contacted.",
        },
    }


def search_policy(query: str) -> dict[str, Any]:
    lowered = query.lower()
    matches = {name: text for name, text in POLICIES.items() if name in lowered or lowered in text.lower()}
    return {
        "tool": "search_policy",
        "result": matches or POLICIES,
    }


def execute_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if tool_name == "get_user_profile":
        return get_user_profile(str(arguments.get("user_id", CURRENT_USER_ID)))
    if tool_name == "refund_order":
        return refund_order(str(arguments.get("order_id", "ORDER-DEMO")), float(arguments.get("amount", 0)))
    if tool_name == "send_email":
        return send_email(
            str(arguments.get("to", "nobody@example.local")),
            str(arguments.get("subject", "Demo subject")),
            str(arguments.get("body", "Demo body")),
        )
    if tool_name == "search_policy":
        return search_policy(str(arguments.get("query", "")))
    return {"tool": tool_name, "error": "unknown simulated tool"}
