# Research & differentiation notes

**Prepared:** 17 October 2026

## Problem evidence

OWASP's GenAI guidance describes prompt injection via direct inputs or untrusted external content such as documents, webpages, and other retrieved material. It also warns that prompt injection cannot be solved by prompt wording alone. MITRE ATT&CK includes indirect prompt injection as technique T1698 and AI-enabled exfiltration as T1700. OWASP's excessive-agency guidance recommends reducing unnecessary tool capabilities, reducing permissions, and requiring human review of privileged operations.

## Strategic choice

Do not submit “AI phishing detector” or “AI cybersecurity chatbot.” They are broad and easy to commoditize. Anchor the idea in one operational question:

**Can an email, document, or ticket expand an AI agent's permissions beyond the original user's task?**

TrustFence compares source-of-authority (the user's original intent) with instructions inside untrusted content, and enforces the result at an action boundary. An explainable scope-drift diff helps a reviewer understand both the action and the evidence.

## Similar work and honest claims

The OWASP GenAI Security Project includes Assurance-AI, an AI/agentic security assurance platform for repeatable adversarial testing. Therefore, do not claim that no one has considered securing AI agents, prompt injection, human approval, or audit traces. Position TrustFence as a focused, low-friction action-gate concept for untrusted content flowing into existing AI workflows, with an explicit intent-to-action comparison. Validate the specific differentiation through a competitor scan before making stronger claims.

## Practical demo hypothesis

Given a task that asks for read-only summarization, a malicious document may request export/email/delete actions. The testable hypothesis is that an intent-bound policy gate can block those actions while allowing benign read-only summarization. The starter repo contains synthetic examples only; results must be measured on a larger, labeled set before presenting quantitative effectiveness.

## Sources

1. OWASP GenAI Security Project, *OWASP Top 10 for Large Language Model Applications*, published 4 August 2026: https://github.com/GenAI-Security-Project/GenAI-LLM-Top10
2. OWASP GenAI Security Project, *LLM01:2025 Prompt Injection*: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
3. OWASP GenAI Security Project, *LLM06:2025 Excessive Agency*: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
4. MITRE ATT&CK Enterprise, *Indirect Prompt Injection (T1698)*: https://attack.mitre.org/techniques/T1698/
5. MITRE ATT&CK Enterprise, *AI-Enabled Exfiltration (T1700)*: https://attack.mitre.org/techniques/T1700/
6. OWASP GenAI Security Project, *Assurance-AI*, published 4 October 2026: https://genai.owasp.org/solution/assurance-ai/
