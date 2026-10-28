// How a traffic-log row is labelled (UX reorganization 2026-10-28).
//
// access_logs stores no threat severity: the "severity" the log API returns
// is computed from the HTTP status (403 -> CRITICAL, 5xx -> HIGH, ...), so
// the logs page shows what the WAF did with the request instead, and keeps the
// HTTP status as its own column and filter.

export type LogOutcome = 'blocked' | 'rate_limited' | 'error' | 'allowed'

export function logOutcome(status: number): LogOutcome {
  if (status === 403) return 'blocked'
  if (status === 429) return 'rate_limited'
  if (status >= 500) return 'error'
  return 'allowed'
}

export const OUTCOME_LABEL: Record<LogOutcome, string> = {
  blocked: 'Blocked',
  rate_limited: 'Rate limited',
  error: 'Origin error',
  allowed: 'Passed',
}

// The log pipeline stores the placeholder "WAF-CRS" when ModSecurity blocked
// a request without reporting which rule (services/log_normalize.py). That is
// not a rule id, so it is shown as "not recorded" rather than as one.
export const GENERIC_RULE_ID = 'WAF-CRS'

// The inline ML gate's own block or challenge (backend log_normalize.ML_RULE_ID):
// the Gen 3 model's score, not a ModSecurity rule, so never shown as a rule id.
export const ML_RULE_ID = 'ML-GEN3'

export function isMlAction(ruleId: string | null | undefined): boolean {
  return String(ruleId ?? '').trim() === ML_RULE_ID
}

export function realRuleId(ruleId: string | null | undefined): string | null {
  const v = String(ruleId ?? '').trim()
  return v && v !== GENERIC_RULE_ID && v !== ML_RULE_ID ? v : null
}
