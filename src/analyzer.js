'use strict';

// TrustFence reference policy engine. This is deliberately deterministic: model
// output can describe a proposed action, but must never grant authority to it.
const INJECTION_PATTERNS = [
  { id: 'instruction_override', label: 'Instruction override attempt', weight: 28,
    regex: /\b(ignore|disregard|override|forget)\b.{0,60}\b(previous|prior|above|earlier|user|system|developer)\b.{0,30}\b(instruction|prompt|message|rule|request|policy)s?\b/i },
  { id: 'secret_request', label: 'Attempt to reveal protected instructions or secrets', weight: 24,
    regex: /\b(reveal|print|dump|show|expose|extract|disclose)\b.{0,45}\b(system prompt|api key|password|secret|token|credential|private key|hidden instruction)s?\b/i },
  { id: 'concealment', label: 'Concealment instruction', weight: 18,
    regex: /\b(do not|don't|never)\s+(tell|inform|notify|show)\b.{0,35}\b(user|owner|security|administrator)\b/i },
  { id: 'security_disable', label: 'Attempt to weaken security controls', weight: 24,
    regex: /\b(disable|turn off|bypass|remove)\b.{0,35}\b(mfa|2fa|logging|audit|security|approval|authentication|monitoring)\b/i },
  { id: 'role_impersonation', label: 'Privilege or role impersonation', weight: 20,
    regex: /\b(you are now|act as|pretend to be)\b.{0,45}\b(admin|administrator|system|developer|security officer|owner)\b/i },
];

const ACTION_PATTERNS = [
  { id: 'send_email', label: 'Send or forward a message', severity: 'high', weight: 18,
    regex: /\b(send|forward|email|mail)\b.{0,100}(\b(to|outside|external|recipient)\b|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i },
  { id: 'export_data', label: 'Export, copy, upload, or share data', severity: 'high', weight: 22,
    regex: /\b(export|download|upload|exfiltrate|copy out|share|attach)\b.{0,80}\b(data|file|database|spreadsheet|records|document|secret|credential|key|report|invoice|customer|employee|repository)\b/i },
  { id: 'delete_data', label: 'Delete or erase records', severity: 'high', weight: 20,
    regex: /\b(delete|erase|wipe|remove)\b.{0,55}\b(email|message|file|document|record|logs?|audit trail|backup|database|history)\b/i },
  { id: 'change_permissions', label: 'Change access or weaken authentication', severity: 'critical', weight: 25,
    regex: /\b(grant|give|assign|escalate|change|update|revoke)\b.{0,55}\b(admin|administrator|permission|access|privilege|role|account)\b|\b(disable|turn off|bypass)\b.{0,30}\b(mfa|2fa|logging|authentication|security)\b/i },
  { id: 'execute_code', label: 'Execute a command or script', severity: 'critical', weight: 28,
    regex: /\b(run|execute|invoke)\b.{0,65}\b(shell|powershell|command|script|terminal|code|macro)\b|\bcurl\b.{0,120}\bhttps?:\/\//i },
  { id: 'reveal_secrets', label: 'Access or disclose secrets', severity: 'critical', weight: 28,
    regex: /\b(reveal|print|dump|show|expose|extract|send|read)\b.{0,45}\b(api key|password|secret|token|credential|system prompt|private key|recovery code)s?\b/i },
];

const AUTHORIZATION_RULES = {
  send_email: /\b(send|forward|email|mail)\b.{0,100}(\b(to|recipient)\b|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i,
  export_data: /\b(export|download|upload|share|attach|copy)\b.{0,60}\b(data|file|database|spreadsheet|records|document|report|invoice|repository)\b/i,
  delete_data: /\b(delete|erase|wipe|remove)\b.{0,55}\b(email|message|file|document|record|logs?|audit trail|backup|database|history)\b/i,
  change_permissions: /\b(grant|give|assign|escalate|change|update|revoke)\b.{0,55}\b(admin|administrator|permission|access|privilege|role|account)\b/i,
  execute_code: /\b(run|execute|invoke)\b.{0,65}\b(shell|powershell|command|script|terminal|code|macro)\b/i,
  reveal_secrets: /\b(reveal|print|dump|show|expose|extract|read)\b.{0,45}\b(api key|password|secret|token|credential|system prompt|private key|recovery code)s?\b/i,
};
const DENIAL = /\b(do not|don't|never|must not|without approval|not allowed to|no permission to)\b/i;

function evidenceFor(text, regex, before = 55, after = 85) {
  const match = regex.exec(text);
  if (!match) return null;
  const start = Math.max(0, match.index - before);
  const end = Math.min(text.length, match.index + match[0].length + after);
  return text.slice(start, end).replace(/\s+/g, ' ').trim();
}

function actionsFromIntent(intent) {
  const authorized = [];
  for (const [action, regex] of Object.entries(AUTHORIZATION_RULES)) {
    const match = regex.exec(intent);
    if (!match) continue;
    const context = intent.slice(Math.max(0, match.index - 35), match.index + match[0].length + 20);
    if (!DENIAL.test(context)) authorized.push(action);
  }
  // Secret disclosure is never authorized by an ordinary natural-language request.
  return [...new Set(authorized)];
}

function analyze({ userIntent = '', untrustedContent = '' } = {}) {
  const intent = String(userIntent).trim();
  const content = String(untrustedContent).trim();
  if (!intent || !content) {
    return { error: 'Both the original user intent and the untrusted content are required.' };
  }
  const authorizedActions = actionsFromIntent(intent);
  const injections = [];
  const actions = [];
  let score = 0;

  for (const p of INJECTION_PATTERNS) {
    const evidence = evidenceFor(content, p.regex);
    if (evidence) {
      injections.push({ id: p.id, label: p.label, evidence, weight: p.weight });
      score += p.weight;
    }
  }
  for (const p of ACTION_PATTERNS) {
    const evidence = evidenceFor(content, p.regex);
    if (evidence) {
      const authorizedByIntent = authorizedActions.includes(p.id) && p.id !== 'reveal_secrets';
      actions.push({
        id: p.id,
        label: p.label,
        severity: p.severity,
        evidence,
        authorizedByIntent,
        source: 'untrusted_content',
      });
      score += p.weight;
    }
  }

  const unauthorizedActions = actions.filter(a => !a.authorizedByIntent);
  const hasInjection = injections.length > 0;
  const hasCritical = actions.some(a => a.severity === 'critical');
  let decision;
  let decisionTitle;
  let rationale;
  if (unauthorizedActions.length > 0) {
    decision = 'BLOCK';
    decisionTitle = 'Block: action exceeds the user intent';
    rationale = 'The content being processed requests a side effect or sensitive access that the user did not explicitly authorize. Untrusted content cannot grant new permissions.';
  } else if (hasInjection) {
    decision = 'REVIEW';
    decisionTitle = 'Hold for human review';
    rationale = 'Instruction-like content attempts to change the assistant’s role or handling rules. Keep processing read-only until a person reviews the evidence.';
  } else if (actions.length > 0 && actions.every(a => a.authorizedByIntent)) {
    decision = 'APPROVAL_REQUIRED';
    decisionTitle = 'Human approval required';
    rationale = 'The original request appears to authorize a side effect, but the prototype never executes one. A production connector must validate identity, scope, recipient, and explicit confirmation.';
  } else {
    decision = 'PASS_READ_ONLY';
    decisionTitle = 'Pass in read-only mode';
    rationale = 'No covered high-risk action or injection pattern was detected. This is not a guarantee that the content is safe; keep untrusted content sandboxed.';
  }

  return {
    product: 'TrustFence',
    analysisMode: 'RULES_ONLY',
    decision,
    decisionTitle,
    rationale,
    riskScore: Math.min(100, score),
    scoreMeaning: 'Heuristic severity indicator, not a probability or a validated model score.',
    originalIntent: intent,
    authorizedActions,
    detectedInjectionSignals: injections,
    detectedActions: actions,
    unauthorizedActions: unauthorizedActions.map(a => a.id),
    scopeDrift: unauthorizedActions.length > 0,
    highRisk: unauthorizedActions.length > 0 || hasCritical || hasInjection,
    safeNextStep: decision === 'BLOCK'
      ? 'Stop the proposed side effect. Show the evidence and ask the user to restate the intended task through a trusted channel.'
      : decision === 'REVIEW'
        ? 'Keep the task read-only. Require a reviewer to inspect the highlighted text before any tool call.'
        : decision === 'APPROVAL_REQUIRED'
          ? 'Display a permission-scoped action preview and require explicit human confirmation before execution.'
          : 'Continue with read-only summarization only; do not infer new permissions from the document.',
    limitations: [
      'This MVP uses transparent string/regex rules and can miss paraphrases or produce false positives.',
      'It does not connect to email, files, identity systems, or an actual AI agent, and it does not execute blocked actions.',
      'A risk score is a heuristic severity indicator, not a probability, accuracy claim, or certification.'
    ]
  };
}

function mergeSemanticFindings(result, semantic, userIntent, untrustedContent) {
  if (!result || result.error || !semantic || !semantic.ok) return result;
  const authorized = actionsFromIntent(userIntent);
  const injectionMap = new Map((result.detectedInjectionSignals || []).map(x => [x.evidence.toLowerCase(), x]));
  for (const finding of semantic.injectionSignals || []) {
    // Adapter already verified the quote is present verbatim in the content.
    if (!injectionMap.has(finding.evidence.toLowerCase())) {
      injectionMap.set(finding.evidence.toLowerCase(), { ...finding, source: 'local_llm' });
    }
  }
  const actionMap = new Map((result.detectedActions || []).map(x => [`${x.id}:${x.evidence.toLowerCase()}`, x]));
  for (const finding of semantic.actions || []) {
    const key = `${finding.id}:${finding.evidence.toLowerCase()}`;
    if (!actionMap.has(key)) {
      actionMap.set(key, {
        ...finding,
        authorizedByIntent: authorized.includes(finding.id) && finding.id !== 'reveal_secrets',
        source: 'local_llm'
      });
    }
  }
  result.detectedInjectionSignals = [...injectionMap.values()];
  result.detectedActions = [...actionMap.values()];
  result.unauthorizedActions = result.detectedActions.filter(a => !a.authorizedByIntent).map(a => a.id);
  result.scopeDrift = result.unauthorizedActions.length > 0;
  const hasInjection = result.detectedInjectionSignals.length > 0;
  const hasCritical = result.detectedActions.some(a => a.severity === 'critical');
  let score = result.detectedInjectionSignals.reduce((n, x) => n + (Number(x.weight) || 12), 0);
  score += result.detectedActions.reduce((n, x) => n + (x.severity === 'critical' ? 25 : 18), 0);
  result.riskScore = Math.min(100, score);
  result.highRisk = result.scopeDrift || hasCritical || hasInjection;
  if (result.unauthorizedActions.length > 0) {
    result.decision = 'BLOCK';
    result.decisionTitle = 'Block: action exceeds the user intent';
    result.rationale = 'The combined local analysis found a side effect or sensitive access in untrusted content that the user did not explicitly authorize. The local model can identify risks but cannot grant permission.';
    result.safeNextStep = 'Stop the proposed side effect. Show the evidence and ask the user to restate the intended task through a trusted channel.';
  } else if (hasInjection) {
    result.decision = 'REVIEW';
    result.decisionTitle = 'Hold for human review';
    result.rationale = 'The semantic and rule-based checks detected instruction-like content. Keep processing read-only until a person reviews the evidence.';
    result.safeNextStep = 'Keep the task read-only. Require a reviewer to inspect the highlighted text before any tool call.';
  } else if (result.detectedActions.length > 0) {
    result.decision = 'APPROVAL_REQUIRED';
    result.decisionTitle = 'Human approval required';
    result.rationale = 'A side effect was identified in the content, but this prototype never executes one. A production connector must validate identity, scope, destination, and explicit confirmation.';
    result.safeNextStep = 'Display a permission-scoped action preview and require explicit human confirmation before execution.';
  } else {
    result.decision = 'PASS_READ_ONLY';
    result.decisionTitle = 'Pass in read-only mode';
    result.rationale = 'No covered high-risk action or injection pattern was detected. This is not a guarantee that the content is safe; keep untrusted content sandboxed.';
    result.safeNextStep = 'Continue with read-only summarization only; do not infer new permissions from the document.';
  }
  result.analysisMode = 'OLLAMA_PLUS_RULES';
  result.semanticScan = { enabled: true, ok: true, model: semantic.model, message: semantic.message, summary: semantic.summary || '' };
  return result;
}

module.exports = { analyze, actionsFromIntent, mergeSemanticFindings };
