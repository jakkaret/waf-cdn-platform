import { describe, it, expect } from 'vitest'
import { onCount, originHealth, protectionStates } from './originSummary'
import type { OriginOverview } from '../types'

const base = { status: 'active' as const, is_tunnel: false, live_connected: null, health: 'up' as const }

describe('originHealth', () => {
  it('is online for an active origin with a live domain', () => {
    expect(originHealth(base, { total: 1, verified: 1 })).toMatchObject({ label: 'Online', tone: 'ok', needsAction: false })
  })
  it('puts a disconnected tunnel first, pointing at the tunnels page', () => {
    const h = originHealth({ ...base, is_tunnel: true, live_connected: false })
    expect(h).toMatchObject({ label: 'Tunnel offline', tone: 'bad', rank: 0, needsAction: true })
    expect(h.step?.path).toBe('/tunnels')
  })
  it('reports pending setup and pending DNS as warnings with a fix', () => {
    expect(originHealth({ ...base, status: 'pending' })).toMatchObject({ label: 'Pending setup', tone: 'warn', step: { tab: 'domains' } })
    expect(originHealth(base, { total: 2, verified: 0 })).toMatchObject({ label: 'Pending DNS', tone: 'warn', step: { tab: 'domains' } })
  })
  it('does not call a tunnel origin without domains pending DNS', () => {
    expect(originHealth({ ...base, is_tunnel: true, live_connected: true }, { total: 0, verified: 0 }).label).toBe('Online')
  })
  it('marks an unreachable origin offline and an archived one as archived', () => {
    expect(originHealth({ ...base, status: 'error' }).label).toBe('Offline')
    expect(originHealth({ ...base, status: 'archived' })).toMatchObject({ label: 'Archived', needsAction: false })
  })
})

const prot = (over: Partial<OriginOverview['protection']> = {}): OriginOverview['protection'] => ({
  waf: { custom_rules: 1, decoys: 6 },
  ml: { mode: 'log', challenge_score: 88, block_score: 95 },
  ip: { block: 2, allow: 1 },
  rate: { rules: 0, enabled: 0 },
  shield: { captcha: true, otp: false },
  ...over,
})

describe('protectionStates', () => {
  it('reads each protection from the overview', () => {
    const s = protectionStates(prot())
    expect(s.waf).toEqual({ state: 'on', summary: '1 own rule · 6 trap paths' })
    expect(s.ml).toEqual({ state: 'watch', summary: 'Watching only' })
    expect(s.ip).toEqual({ state: 'on', summary: '2 blocked · 1 allowed' })
    expect(s.rate).toEqual({ state: 'off', summary: 'No limits' })
    expect(s.shield).toEqual({ state: 'on', summary: 'CAPTCHA' })
    expect(onCount(s)).toBe(3)
  })
  it('turns AI blocking on only in enforce mode', () => {
    expect(protectionStates(prot({ ml: { mode: 'enforce', challenge_score: 88, block_score: 95 } })).ml).toEqual({ state: 'on', summary: 'Blocks from 95' })
  })
  it('says unknown, not off, when a store could not be read', () => {
    const s = protectionStates(prot({ ml: null, ip: null, rate: null, shield: { captcha: null, otp: null } }))
    expect([s.ml.state, s.ip.state, s.rate.state, s.shield.state]).toEqual(['unknown', 'unknown', 'unknown', 'unknown'])
    expect(protectionStates(undefined).waf.state).toBe('on')
  })
  it('counts paused rate limits as off', () => {
    expect(protectionStates(prot({ rate: { rules: 2, enabled: 0 } })).rate).toEqual({ state: 'off', summary: '2 limits paused' })
  })
})
