// One status vocabulary and one set of protection states for the Origins
// list, the origin header and the Protection tab, all from real fields:
// the origin record (status, tunnel connectivity) and GET
// /api/origins/overview (services/origin_overview.py). Nothing here guesses
// or suggests; a value the backend could not read shows as unknown.

import type { Origin, OriginOverview } from '../types'
import type { OriginTabId } from '../components/layout/navigation'

export type Tone = 'ok' | 'warn' | 'bad' | 'off'

export interface Health {
  label: string
  tone: Tone
  // Lower sorts first in "Needs action".
  rank: number
  needsAction: boolean
  step?: { label: string; tab?: OriginTabId; path?: string }
}

export function originHealth(o: Pick<Origin, 'status' | 'is_tunnel' | 'live_connected' | 'health'>, domains?: OriginOverview['domains']): Health {
  if (o.status === 'archived') return { label: 'Archived', tone: 'off', rank: 9, needsAction: false }
  if (o.status === 'pending') {
    return { label: 'Pending setup', tone: 'warn', rank: 1, needsAction: true, step: { label: 'Finish the domain setup', tab: 'domains' } }
  }
  if (o.is_tunnel && o.live_connected === false) {
    return { label: 'Tunnel offline', tone: 'bad', rank: 0, needsAction: true, step: { label: 'Check the tunnel agent', path: '/tunnels' } }
  }
  if (o.status === 'error' || o.health === 'down') {
    return { label: 'Offline', tone: 'bad', rank: 0, needsAction: true, step: { label: 'Check your server', tab: 'overview' } }
  }
  if (o.status === 'inactive') {
    return { label: 'Inactive', tone: 'warn', rank: 2, needsAction: true, step: { label: 'Check the origin settings', tab: 'overview' } }
  }
  if (!o.is_tunnel && domains && domains.total > 0 && domains.verified === 0) {
    return { label: 'Pending DNS', tone: 'warn', rank: 1, needsAction: true, step: { label: 'Point DNS to the edge', tab: 'domains' } }
  }
  return { label: 'Online', tone: 'ok', rank: 5, needsAction: false }
}

export type ProtKey = 'waf' | 'ml' | 'ip' | 'rate' | 'shield'
export const PROT_KEYS: ProtKey[] = ['waf', 'ml', 'ip', 'rate', 'shield']

// The old tab each protection lives in, so links and quick search keep working.
export const PROT_TAB: Record<ProtKey, OriginTabId> = {
  waf: 'waf',
  ml: 'ml',
  ip: 'ip-access',
  rate: 'rate-limits',
  shield: 'shield',
}

export const PROT_META: Record<ProtKey, { name: string; tech: string; desc: string }> = {
  waf: { name: 'Attack rules', tech: 'WAF · OWASP CRS', desc: 'Blocks SQL injection, cross-site scripting and other known attack patterns. Always on.' },
  ml: { name: 'AI blocking', tech: 'ML risk score', desc: 'Scores every request 0–100; in enforce mode high scores are challenged or blocked.' },
  ip: { name: 'IP rules', tech: 'IP access', desc: 'Block an address or range, or always let a trusted one through.' },
  rate: { name: 'Rate limits', tech: 'Request floods', desc: 'Caps how many requests one visitor can send to a path in a time window.' },
  shield: { name: 'Login protection', tech: 'Bot & login shield', desc: 'A CAPTCHA or an email code before someone reaches a login page.' },
}

export type ProtState = 'on' | 'watch' | 'off' | 'unknown'
export const PROT_STATE_LABEL: Record<ProtState, string> = { on: 'On', watch: 'Watching', off: 'Off', unknown: 'Unknown' }

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

export function protectionStates(p: OriginOverview['protection'] | null | undefined): Record<ProtKey, { state: ProtState; summary: string }> {
  const waf = p?.waf
  const ml = p?.ml
  const ip = p?.ip
  const rate = p?.rate
  const shield = p?.shield
  const shieldParts = [shield?.captcha ? 'CAPTCHA' : '', shield?.otp ? 'Email code' : ''].filter(Boolean)
  return {
    // CRS runs for every origin; the summary is the owner's additions.
    waf: {
      state: 'on',
      summary:
        waf && waf.custom_rules !== null && waf.decoys !== null
          ? `${plural(waf.custom_rules, 'own rule')} · ${plural(waf.decoys, 'trap path')}`
          : 'OWASP CRS',
    },
    ml: !ml
      ? { state: 'unknown', summary: '—' }
      : ml.mode === 'enforce'
      ? { state: 'on', summary: `Blocks from ${ml.block_score}` }
      : { state: 'watch', summary: 'Watching only' },
    ip: !ip
      ? { state: 'unknown', summary: '—' }
      : ip.block + ip.allow > 0
      ? { state: 'on', summary: [ip.block ? `${ip.block} blocked` : '', ip.allow ? `${ip.allow} allowed` : ''].filter(Boolean).join(' · ') }
      : { state: 'off', summary: 'No rules' },
    rate: !rate
      ? { state: 'unknown', summary: '—' }
      : rate.enabled > 0
      ? { state: 'on', summary: plural(rate.enabled, 'limit') }
      : { state: 'off', summary: rate.rules ? `${plural(rate.rules, 'limit')} paused` : 'No limits' },
    shield:
      !shield || (shield.captcha === null && shield.otp === null)
        ? { state: 'unknown', summary: '—' }
        : shieldParts.length
        ? { state: 'on', summary: shieldParts.join(' + ') }
        : { state: 'off', summary: 'Not used' },
  }
}

export const onCount = (s: Record<ProtKey, { state: ProtState }>) => PROT_KEYS.filter((k) => s[k].state === 'on').length
