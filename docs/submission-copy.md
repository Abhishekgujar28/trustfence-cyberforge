# CyberForge submission form — copy/paste draft

**Theme:** AI & Cybersecurity

**Problem Statement:** Select the closest option provided by the HackCulture dropdown. Based on the screenshot, the visible choice begins “Innovative Solution for AI & Cyber...”. Do not assume the full official wording without checking the dropdown.

**Project Title:** TrustFence: Intent-Bound AI Action Firewall

**Briefly explain about your idea:**

AI agents increasingly read emails, tickets, webpages, and documents and may have access to tools such as email, file storage, and internal APIs. Those external sources are untrusted data, yet they can contain instructions designed to hijack an agent into disclosing secrets, exporting files, deleting evidence, or changing permissions. A generic “malicious text” warning is not enough: teams need to know whether the proposed action exceeds what the user actually asked the agent to do.

TrustFence is an evidence-first, intent-bound action firewall. It creates a narrow action contract from the original trusted user request, scans the content being processed for instruction overrides and risky proposed actions, and compares each finding against the contract. If a document tries to expand the agent’s authority, TrustFence blocks the action and shows the exact text and reason. Ambiguous instruction attempts are held for human review; legitimate side effects still require explicit approval. The MVP demonstrates this with synthetic email/document scenarios, a browser dashboard, a deterministic policy engine, evidence snippets, and automated tests. It does not execute real email, file, or account actions.

Our key design choice is to separate **understanding** from **authorization**: an AI model may help interpret natural language, but it must never grant permissions. The policy gate, least-privilege action scopes, and human approval remain independently enforced. We will evaluate the approach using labeled benign and adversarial scenarios, measuring unauthorized actions blocked, false-block rate, and evidence-review time. This is a prototype proposal, not a claim of perfect prevention or proven accuracy.

**Additional supporting links:** Add the public GitHub repository and live demo once created and deployed. For now, the local ZIP is a starter bundle and is not a public repository URL.

**Hackathon participation history:** Answer truthfully in the form; do not guess on the team's behalf.

**Offline Bengaluru attendance on 31 Oct–1 Nov:** Answer based on whether every required attendee can genuinely travel and attend. Do not select “Yes” just to improve odds if travel is uncertain.

## Recommended project title alternatives

1. TrustFence: Intent-Bound AI Action Firewall (recommended)
2. ScopeLock: Stop AI Agents from Overstepping User Intent
3. ProofGate: Evidence-First Guardrails for AI Agents

## Before clicking Save

- Confirm theme and full problem statement from the dropdown.
- Confirm whether the form imposes a file-size limit and accepted formats.
- Upload the generated PPTX idea deck.
- Add a public repo URL only after pushing the code to a repository you intend to make public.
- Choose hackathon history and offline attendance truthfully.
- Take a screenshot of the saved submission and confirm the phase shows submitted/saved.
