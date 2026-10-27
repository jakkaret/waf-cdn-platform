// Per-origin ML protection (Origin -> ML Protection tab). Same limits as
// dashboard/backend/services/ml_gate.py.

export const CHALLENGE_RANGE = [50, 99] as const
export const BLOCK_RANGE = [51, 100] as const
export const SUGGESTED = { challenge: 88, block: 95 } as const

/** Why these bands cannot be saved, or null when they can. */
export function bandError(challenge: number | null, block: number): string | null {
  if (!Number.isInteger(block) || block < BLOCK_RANGE[0] || block > BLOCK_RANGE[1]) {
    return `Block score must be a whole number from ${BLOCK_RANGE[0]} to ${BLOCK_RANGE[1]}.`
  }
  if (challenge === null) return null
  if (!Number.isInteger(challenge) || challenge < CHALLENGE_RANGE[0] || challenge > CHALLENGE_RANGE[1]) {
    return `Challenge score must be a whole number from ${CHALLENGE_RANGE[0]} to ${CHALLENGE_RANGE[1]}.`
  }
  if (challenge >= block) return 'The challenge score must be lower than the block score.'
  return null
}

export interface Band {
  key: 'pass' | 'challenge' | 'block'
  from: number
  to: number
  label: string
}

/** The 0-100 score split into what happens to a request, lowest first. */
export function bands(challenge: number | null, block: number): Band[] {
  const out: Band[] = [{ key: 'pass', from: 0, to: challenge ?? block, label: 'Allowed' }]
  if (challenge !== null) out.push({ key: 'challenge', from: challenge, to: block, label: 'Challenge' })
  out.push({ key: 'block', from: block, to: 100, label: 'Block' })
  return out
}

/** "88-94" style range of a band (scores are whole points, the top one is inclusive). */
export function bandRange(b: Band): string {
  if (b.key === 'block') return b.from >= 100 ? '100' : `${b.from}-100`
  return b.to - 1 <= b.from ? `${b.from}` : `${b.from}-${b.to - 1}`
}

export function share(n: number, total: number): string {
  if (!total || !n) return '0%'
  const pct = (n / total) * 100
  if (pct < 0.1) return '<0.1%'
  return `${pct.toFixed(pct < 10 ? 1 : 0)}%`
}

/** Whether saving this form changes the stored setting. */
export function isDirty(
  saved: { mode: string; challenge_score: number | null; block_score: number },
  form: { mode: string; challenge_score: number | null; block_score: number },
): boolean {
  return saved.mode !== form.mode || saved.challenge_score !== form.challenge_score || saved.block_score !== form.block_score
}
