// GET /api/logs/explain/{log_id} answers { explanation: { explain_summary, category,
// matched_token, root_cause_explanation, remediation_hint, confidence_score } }.
// Logs.tsx used to put that object straight into JSX, which React refuses to
// render ("Objects are not valid as a React child") and the page crashed.

export interface LogExplanation {
  summary: string
  category?: string
  matchedToken?: string
  rootCause?: string
  remediation?: string
  /** 0..1 */
  confidence?: number
}

const text = (v: unknown): string | undefined => {
  if (v === null || v === undefined) return undefined
  const s = String(v).trim()
  return s ? s : undefined
}

export function toLogExplanation(res: unknown): LogExplanation {
  const body = (res && typeof res === 'object' ? res : {}) as Record<string, unknown>
  const exp = body.explanation ?? body.analysis
  if (exp && typeof exp === 'object') {
    const e = exp as Record<string, unknown>
    const confidence = Number(e.confidence_score)
    return {
      summary: text(e.explain_summary) ?? text(e.root_cause_explanation) ?? 'No explanation available',
      category: text(e.category),
      matchedToken: text(e.matched_token),
      rootCause: text(e.root_cause_explanation),
      remediation: text(e.remediation_hint),
      confidence: Number.isFinite(confidence) ? Math.min(Math.max(confidence, 0), 1) : undefined,
    }
  }
  return { summary: text(exp) ?? 'No explanation available' }
}

export function confidenceLabel(confidence: number | undefined): string | undefined {
  return confidence === undefined ? undefined : `${Math.round(confidence * 100)}%`
}
