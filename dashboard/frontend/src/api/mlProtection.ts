import { api } from './axios'

// A site's ML protection setting (backend api/ml_protection.py).

export type MlMode = 'log' | 'enforce'

export interface MlProtection {
  origin_id: string
  mode: MlMode
  challenge_score: number | null
  block_score: number
  updated_by: string
  updated_at: string | null
  /** The site's verified hosts the setting applies to. */
  hosts: string[]
  /** Whether the WAF already runs with exactly this setting. */
  applied: boolean
  map_error: string | null
}

export interface MlProtectionInput {
  mode: MlMode
  challenge_score: number | null
  block_score: number
}

export interface MlPreview {
  hours: number
  total: number
  would_block: number
  would_challenge: number
  /** Epoch seconds of the oldest scored request in the window. */
  since: number | null
  examples: { timestamp: number; host: string; method: string; path: string; score: number }[]
}

export const getMlProtection = (originId: string) =>
  api.get<MlProtection>(`/origins/${originId}/ml-protection`).then((r) => r.data)

export const saveMlProtection = (originId: string, body: MlProtectionInput) =>
  api.put<MlProtection>(`/origins/${originId}/ml-protection`, body).then((r) => r.data)

export const previewMlProtection = (originId: string, challengeScore: number | null, blockScore: number) =>
  api
    .get<MlPreview>(`/origins/${originId}/ml-protection/preview`, {
      params: { block_score: blockScore, ...(challengeScore !== null ? { challenge_score: challengeScore } : {}) },
    })
    .then((r) => r.data)
