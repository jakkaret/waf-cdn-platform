import { api } from './axios'
import { MLPendingRule } from '../types'

// One scored request of an origin (backend api/ml_protection.py): its masked
// body, and a rule proposal from it. Owner and Editors only.

export interface MLVerdictDetail {
  timestamp: string
  request_id: string
  host: string
  method: string
  path: string
  query: string
  score: number
  threshold: number
  is_attack: boolean
  detectors: string[]
  body_length: number
  action: 'pass' | 'challenge' | 'block' | null
  /** Masked (secrets and personal data) and cut at 4,096 characters; "" below score 50. */
  body_sample: string
}

export interface MLRuleSuggestion {
  gen3: { is_attack: boolean; attack_probability?: number; threshold?: number }
  suggested_rules: MLPendingRule[]
  suggestion: { created: number; merged: number; reason: string; origin_id: string }
}

export const getMLVerdict = (originId: string, requestId: string) =>
  api.get<MLVerdictDetail>(`/origins/${originId}/ml-verdicts/${encodeURIComponent(requestId)}`).then((r) => r.data)

export const suggestRuleFromVerdict = (originId: string, requestId: string) =>
  api
    .post<MLRuleSuggestion>(`/origins/${originId}/ml-verdicts/${encodeURIComponent(requestId)}/suggest-rule`)
    .then((r) => r.data)
