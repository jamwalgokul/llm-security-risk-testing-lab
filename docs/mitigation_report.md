# Mitigation Report

## Summary

The lab implements two intentionally weak endpoints and two guarded endpoints so testers can compare risk reduction across the same adversarial test cases.

## Vulnerable Mode Behavior

`mock-vulnerable` and `local-vulnerable` demonstrate common failure modes:

- Weak system prompt.
- Fake internal data included directly in context.
- No input filtering.
- No output filtering.
- Broad simulated tool access.
- No approval or confirmation checks.

## Secure Mode Controls

`mock-secure` and `local-secure` add:

- Prompt-injection detection.
- Secret-seeking detection.
- Tool-abuse detection.
- Long-input detection.
- Per-user, per-endpoint in-memory rate limiting.
- Output sanitization for fake secrets and protected instruction leakage.
- JSON security event logging.
- Simulated least-privilege tool policy.

## Tool Policy

| Tool | Policy |
| --- | --- |
| `get_user_profile(user_id)` | Only the current authenticated user is allowed. |
| `refund_order(order_id, amount)` | Amounts above `5000` require `human_approved=true`. |
| `send_email(to, subject, body)` | Requires `confirmed=true`. |
| `search_policy(query)` | Read-only and allowed. |

## Human-in-the-Loop Simulation

Human approval is represented by an explicit API field:

```json
{
  "human_approved": true
}
```

The model cannot set this field through prompt text. This models the core production principle: approval state should live in trusted application control flow, not inside natural language.

Email confirmation is represented similarly:

```json
{
  "confirmed": true
}
```

## Logging

Secure endpoints emit JSON logs for:

- Prompt injection detection.
- Tool-abuse detection.
- Tool policy blocks.
- Long-input blocks.
- Rate-limit blocks.
- Output sanitization.

Each security log includes a request ID, endpoint, severity, event type, and metadata.

## Limitations

- Regex detection is intentionally simple and explainable for lab use.
- Local model behavior is nondeterministic unless the same model, quantization, and settings are used.
- Fake tools do not represent all risks of real tool integration.
- The app uses in-memory rate limiting, which resets on process restart and is not distributed.
- The project should not be exposed directly to untrusted networks.

## Production Hardening Ideas

- Move policy enforcement to a dedicated authorization layer.
- Use structured tool calls with schema validation and allowlists.
- Store approval and confirmation state server-side.
- Add durable audit logging.
- Add streaming output inspection if streaming responses are enabled.
- Add semantic classifiers or dedicated safety models where appropriate.
- Add adversarial regression tests to CI.
