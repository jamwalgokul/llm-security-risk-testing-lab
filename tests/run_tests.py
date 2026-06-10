"""Run adversarial tests against the lab endpoints.

Examples:
    python tests/run_tests.py --endpoint all
    python tests/run_tests.py --endpoint mock-secure --base-url http://localhost:8000
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import yaml


ROOT = Path(__file__).resolve().parents[1]
TEST_CASES_FILE = ROOT / "tests" / "test_cases.yaml"
RESULTS_DIR = ROOT / "tests" / "results"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ENDPOINTS = {
    "mock-vulnerable": "/chat/mock-vulnerable",
    "mock-secure": "/chat/mock-secure",
    "local-vulnerable": "/chat/local-vulnerable",
    "local-secure": "/chat/local-secure",
}

RESULT_FILES = {
    "mock-vulnerable": "mock_vulnerable_results.json",
    "mock-secure": "mock_secure_results.json",
    "local-vulnerable": "local_vulnerable_results.json",
    "local-secure": "local_secure_results.json",
}

SEVERITY_SCORE = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run LLM security lab test cases.")
    parser.add_argument("--endpoint", choices=[*ENDPOINTS.keys(), "all"], default="all")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument(
        "--transport",
        choices=["http", "direct"],
        default="http",
        help="Use HTTP endpoints or call route functions in-process for restricted local sandboxes.",
    )
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    test_cases = load_test_cases()
    selected = list(ENDPOINTS.keys()) if args.endpoint == "all" else [args.endpoint]

    all_results: dict[str, dict[str, Any]] = {}
    for endpoint_name in selected:
        endpoint_results = run_endpoint_tests(endpoint_name, test_cases, args.base_url, args.timeout, args.transport)
        all_results[endpoint_name] = endpoint_results
        write_json(RESULTS_DIR / RESULT_FILES[endpoint_name], endpoint_results)

    report = build_comparison_report(test_cases, all_results)
    (RESULTS_DIR / "comparison_report.md").write_text(report, encoding="utf-8")

    print(f"Completed {len(test_cases)} tests for {', '.join(selected)}")
    print(f"Results written to {RESULTS_DIR}")


def load_test_cases() -> list[dict[str, Any]]:
    with TEST_CASES_FILE.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    return payload["test_cases"]


def run_endpoint_tests(
    endpoint_name: str,
    test_cases: list[dict[str, Any]],
    base_url: str,
    timeout: float,
    transport: str,
) -> dict[str, Any]:
    endpoint_path = ENDPOINTS[endpoint_name]
    url = f"{base_url.rstrip('/')}{endpoint_path}"
    results: list[dict[str, Any]] = []

    for case in test_cases:
        prompt = expand_prompt(case["prompt"])
        try:
            request_payload = {
                "prompt": prompt,
                "user_id": f"runner-{case['id']}",
                "current_user_id": "user-123",
            }
            if transport == "direct":
                payload = call_endpoint_direct(endpoint_name, request_payload)
            else:
                response = requests.post(url, json=request_payload, timeout=timeout)
                response.raise_for_status()
                payload = response.json()
            response_text = str(payload.get("response", ""))
            evaluation = evaluate_case(case, response_text)
            llm_unavailable = endpoint_name.startswith("local") and payload.get("llm_ok") is False
            result = {
                "id": case["id"],
                "category": case["category"],
                "owasp": case["owasp"],
                "mitre_atlas": case["mitre_atlas"],
                "severity": case["severity"],
                "passed": evaluation["passed"] and not llm_unavailable,
                "forbidden_hits": evaluation["forbidden_hits"],
                "response_excerpt": response_text[:500],
                "blocked": payload.get("blocked"),
                "llm_ok": payload.get("llm_ok"),
                "request_id": payload.get("request_id"),
                "guardrail_events": payload.get("guardrail_events", []),
            }
            if llm_unavailable:
                result["error"] = response_text
        except Exception as exc:
            result = {
                "id": case["id"],
                "category": case["category"],
                "owasp": case["owasp"],
                "mitre_atlas": case["mitre_atlas"],
                "severity": case["severity"],
                "passed": False,
                "forbidden_hits": [],
                "error": str(exc),
                "response_excerpt": "",
            }
        results.append(result)

    summary = summarize_results(endpoint_name, results, len(test_cases))
    return {
        "endpoint": endpoint_name,
        "url": url,
        "transport": transport,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "results": results,
    }


def call_endpoint_direct(endpoint_name: str, request_payload: dict[str, Any]) -> dict[str, Any]:
    from app.main import (
        ChatRequest,
        chat_local_secure,
        chat_local_vulnerable,
        chat_mock_secure,
        chat_mock_vulnerable,
    )

    route_map = {
        "mock-vulnerable": chat_mock_vulnerable,
        "mock-secure": chat_mock_secure,
        "local-vulnerable": chat_local_vulnerable,
        "local-secure": chat_local_secure,
    }
    response_model = route_map[endpoint_name](ChatRequest(**request_payload))
    if hasattr(response_model, "model_dump"):
        return response_model.model_dump()
    return response_model.dict()


def expand_prompt(prompt: str) -> str:
    if "{{LONG_INPUT_12000}}" in prompt:
        filler = "audit-noise " * 1200
        return prompt.replace("{{LONG_INPUT_12000}}", filler)
    return prompt


def evaluate_case(case: dict[str, Any], response_text: str) -> dict[str, Any]:
    lowered = response_text.lower()
    forbidden_hits = [term for term in case.get("forbidden_terms", []) if str(term).lower() in lowered]
    return {"passed": not forbidden_hits, "forbidden_hits": forbidden_hits}


def summarize_results(endpoint_name: str, results: list[dict[str, Any]], total_tests: int) -> dict[str, Any]:
    failures = [item for item in results if not item["passed"]]
    risk_score = sum(SEVERITY_SCORE.get(item["severity"], 2) for item in failures)
    max_risk_score = sum(SEVERITY_SCORE.get(item["severity"], 2) for item in results)
    severity_breakdown = Counter(item["severity"] for item in failures)
    category_breakdown = Counter(item["category"] for item in failures)
    return {
        "endpoint": endpoint_name,
        "total_tests": total_tests,
        "passed": total_tests - len(failures),
        "failed": len(failures),
        "risk_score": risk_score,
        "max_risk_score": max_risk_score,
        "risk_percentage": round((risk_score / max_risk_score) * 100, 2) if max_risk_score else 0,
        "severity_breakdown": dict(severity_breakdown),
        "category_breakdown": dict(category_breakdown),
    }


def build_comparison_report(test_cases: list[dict[str, Any]], all_results: dict[str, dict[str, Any]]) -> str:
    lines = [
        "# LLM Security Risk Testing Comparison Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Total tests: {len(test_cases)}",
        "",
        "## Endpoint Summary",
        "",
        "| Endpoint | Passed | Failed | Risk Score | Risk % |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]

    for endpoint_name, payload in all_results.items():
        summary = payload["summary"]
        lines.append(
            f"| {endpoint_name} | {summary['passed']} | {summary['failed']} | "
            f"{summary['risk_score']}/{summary['max_risk_score']} | {summary['risk_percentage']}% |"
        )

    lines.extend(["", "## Risk Reduction", ""])
    lines.extend(risk_reduction_lines(all_results))

    lines.extend(["", "## Severity Breakdown", ""])
    for endpoint_name, payload in all_results.items():
        lines.append(f"### {endpoint_name}")
        breakdown = payload["summary"]["severity_breakdown"]
        if not breakdown:
            lines.append("No failures.")
        else:
            for severity in ["Critical", "High", "Medium", "Low"]:
                if severity in breakdown:
                    lines.append(f"- {severity}: {breakdown[severity]}")
        lines.append("")

    lines.extend(["## OWASP Mapping Summary", ""])
    lines.extend(mapping_summary_lines(test_cases, all_results, "owasp"))

    lines.extend(["", "## MITRE ATLAS Mapping Summary", ""])
    lines.extend(mapping_summary_lines(test_cases, all_results, "mitre_atlas"))

    lines.extend(["", "## Top Failed Cases", ""])
    lines.extend(top_failed_cases_lines(all_results))

    lines.extend(
        [
            "",
            "## Mitigations Applied",
            "",
            "- Input validation for prompt injection, leakage, and tool-abuse patterns.",
            "- Output filtering for fake secrets and protected instruction leakage.",
            "- Least-privilege policy for simulated tools.",
            "- Human approval simulation for refunds above 5000.",
            "- Explicit confirmation requirement for simulated email sending.",
            "- Current-user-only profile access.",
            "- Rate limiting and long-input detection before model calls.",
            "- JSON security event logging from secure endpoints.",
            "",
            "## Limitations",
            "",
            "- Regex guardrails are transparent for lab use and are not a substitute for production controls.",
            "- Local model behavior can vary by model file, quantization, prompt template, and decoding settings.",
            "- The tools are fake and intentionally do not prove integration safety for real services.",
            "- Passing these tests does not mean an LLM application is secure against adaptive attackers.",
        ]
    )
    return "\n".join(lines) + "\n"


def risk_reduction_lines(all_results: dict[str, dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    pairs = [("mock-vulnerable", "mock-secure"), ("local-vulnerable", "local-secure")]
    for vulnerable, secure in pairs:
        if vulnerable not in all_results or secure not in all_results:
            continue
        vulnerable_score = all_results[vulnerable]["summary"]["risk_score"]
        secure_score = all_results[secure]["summary"]["risk_score"]
        if vulnerable_score == 0:
            reduction = 0.0
        else:
            reduction = ((vulnerable_score - secure_score) / vulnerable_score) * 100
        lines.append(f"- {vulnerable} to {secure}: {reduction:.2f}% risk reduction")
    if not lines:
        lines.append("Risk reduction requires both vulnerable and secure endpoint results.")
    return lines


def mapping_summary_lines(
    test_cases: list[dict[str, Any]],
    all_results: dict[str, dict[str, Any]],
    field_name: str,
) -> list[str]:
    total_by_mapping = Counter(case[field_name] for case in test_cases)
    failures_by_endpoint: dict[str, Counter[str]] = {}
    for endpoint_name, payload in all_results.items():
        failures_by_endpoint[endpoint_name] = Counter(
            item[field_name] for item in payload["results"] if not item["passed"]
        )

    lines = ["| Mapping | Total Cases | " + " | ".join(f"{name} Failures" for name in all_results) + " |"]
    lines.append("| --- | ---: | " + " | ".join("---:" for _ in all_results) + " |")
    for mapping, total in sorted(total_by_mapping.items()):
        failure_cells = [str(failures_by_endpoint[name].get(mapping, 0)) for name in all_results]
        lines.append(f"| {mapping} | {total} | " + " | ".join(failure_cells) + " |")
    return lines


def top_failed_cases_lines(all_results: dict[str, dict[str, Any]]) -> list[str]:
    rows: list[dict[str, Any]] = []
    for endpoint_name, payload in all_results.items():
        for item in payload["results"]:
            if not item["passed"]:
                rows.append(
                    {
                        "endpoint": endpoint_name,
                        "id": item["id"],
                        "severity": item["severity"],
                        "score": SEVERITY_SCORE.get(item["severity"], 2),
                        "category": item["category"],
                        "hits": ", ".join(item.get("forbidden_hits", [])) or item.get("error", "request failed"),
                    }
                )
    rows.sort(key=lambda row: row["score"], reverse=True)
    if not rows:
        return ["No failed cases."]
    lines = ["| Endpoint | Case | Severity | Category | Evidence |", "| --- | --- | --- | --- | --- |"]
    for row in rows[:15]:
        lines.append(
            f"| {row['endpoint']} | {row['id']} | {row['severity']} | {row['category']} | {row['hits']} |"
        )
    return lines


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
