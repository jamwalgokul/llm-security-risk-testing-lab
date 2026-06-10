# Threat Model

## Scope

This lab evaluates a local LLM application wrapper around an LM Studio model. It uses fake secrets, fictional internal context, and simulated tools only.

## Assets

- Protected system and developer instructions.
- Fake internal data:
  - `INTERNAL_API_KEY=sk-fake-local-demo-12345`
  - `ADMIN_EMAIL=admin@acmebank.local`
  - `REFUND_LIMIT=50000`
- Simulated tool authority:
  - Refunds
  - Email sending
  - User profile reads
  - Policy search
- Local machine compute resources.
- Security logs and test results.

## Trust Boundaries

- User prompt to FastAPI request body.
- FastAPI application to LM Studio local server.
- Application guardrails to model output.
- Application tool policy to simulated tool execution.
- Test runner to API endpoints.

## Attacker Goals

- Override system or developer instructions.
- Extract fake internal secrets.
- Leak protected prompt text.
- Trigger unsafe simulated tool actions.
- Bypass human approval or confirmation.
- Abuse long inputs or excessive output to consume resources.
- Poison retrieved or untrusted content so it is treated as trusted instruction.

## Attack Surfaces

- `/chat/local-vulnerable` weak prompt path.
- `/chat/local-secure` guardrail and policy decisions.
- Prompt text that mixes instructions with untrusted retrieved content.
- Model output that may contain fake secrets or hidden instruction text.
- Tool-like natural language requests.

## Assumptions

- LM Studio runs only on the local host.
- The local model is not treated as a security boundary.
- Tools are fake and deterministic.
- Users can send adversarial prompts.
- The lab is not exposed to the public internet.

## Controls

- Input validation for prompt injection and secret-seeking patterns.
- Tool-abuse detection before tool simulation.
- Least-privilege simulated tool policy.
- Human approval simulation for refunds above `5000`.
- Explicit confirmation simulation for email.
- Current-user-only profile access.
- Output sanitization for fake secrets and protected-instruction leakage.
- Rate limiting and long-input checks.
- JSON security event logging.

## Residual Risk

Regex guardrails can be bypassed by adaptive phrasing. A production system should layer deterministic controls with robust authorization, trusted tool gateways, model-independent policy enforcement, monitoring, and red-team testing.
