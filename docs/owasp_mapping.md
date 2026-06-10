# OWASP Mapping

The test suite maps to the OWASP Top 10 for LLM and GenAI Applications 2025. Reference:

https://genai.owasp.org/llm-top-10/

| OWASP Risk | Covered By | Lab Focus | Primary Mitigations |
| --- | --- | --- | --- |
| LLM01 Prompt Injection | T001-T010, T035-T039 | Direct jailbreaks and indirect instructions in untrusted content | Input detection, refusal path, trust-boundary wording |
| LLM02 Sensitive Information Disclosure | T016-T020 | Fake credential and internal data extraction | Output filtering, secret-pattern detection |
| LLM04 Data and Model Poisoning | T040-T043 | Poisoned RAG snippets and fake policy updates | Treat retrieval as untrusted, block risky follow-on actions |
| LLM05 Improper Output Handling | T031-T034 | Encoded, structured, markdown, and split secret leakage | Sanitization and forbidden-term checks |
| LLM06 Excessive Agency | T021-T030, T044-T047 | Risky tool use, overbroad autonomy, approval bypass | Least-privilege tool policy and human approval simulation |
| LLM07 System Prompt Leakage | T011-T015 | Attempts to print hidden prompt or developer text | Prompt-leakage detection and output redaction |
| LLM10 Unbounded Consumption | T048-T050 | Long input and excessive output requests | Input length limits and rate limiting |

## Notes

The lab does not deeply test every OWASP category. `LLM03 Supply Chain`, `LLM08 Vector and Embedding Weaknesses`, and `LLM09 Misinformation` are documented but not the central focus because this project does not download models programmatically, build a real vector store, or evaluate factual accuracy at scale.
