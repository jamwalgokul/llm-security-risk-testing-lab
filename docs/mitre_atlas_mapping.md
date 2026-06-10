# MITRE ATLAS Mapping

Reference:

https://atlas.mitre.org/

This lab uses high-level MITRE ATLAS-aligned labels in `tests/test_cases.yaml` rather than asserting a complete technique catalog implementation.

| ATLAS-Aligned Area | Covered By | Example Test Intent | Mitigations |
| --- | --- | --- | --- |
| Prompt Injection | T001, T035-T039 | User or retrieved text tries to override trusted instructions | Injection pattern detection and refusal |
| Defense Evasion | T002-T010, T031, T044-T047 | Jailbreak framing, encoded output, approval bypass | Guardrails, output filtering, policy state outside prompt |
| Discovery | T011-T015 | Probe for hidden prompts and internal variables | Protected-instruction refusal and sanitization |
| Credential Access | T016-T017 | Ask for fake API keys or tokens | Secret leakage detection and redaction |
| Exfiltration | T018-T020, T032-T033 | Extract fake internal contacts and config values | Output scanning and safe response templates |
| Execution | T026-T030 | Trigger simulated tools | Least-privilege simulated tool policy |
| Privilege Escalation | T023, T028 | Access another user's profile | Current-user-only checks |
| Data Poisoning | T040-T043 | Poisoned RAG or knowledge-base instructions | Treat retrieved content as untrusted |
| Resource Hijacking | T048-T050 | Long input or excessive generation requests | Length and rate controls |
| Impact | T021-T025 | Financial or messaging side effects through tools | Approval, confirmation, and safe defaults |

## Interpretation

The mapping is for defensive lab reporting. It is not a substitute for a full ATLAS assessment, threat-intelligence program, or production red-team exercise.
