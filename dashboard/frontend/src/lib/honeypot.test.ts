import { describe, it, expect } from 'vitest'
import type { HoneypotSession } from '../api/honeypot'
import { csvCell, formatSpan, iocCsv, STAGES, STAGE_META } from './honeypot'

const session = (over: Partial<HoneypotSession> = {}): HoneypotSession => ({
  id: 'abc-1800000000',
  actor_id: 'abc',
  first_seen: '2026-10-28T03:00:00+00:00',
  last_seen: '2026-10-28T03:05:00+00:00',
  duration_seconds: 300,
  events: 4,
  ips: ['198.51.100.20'],
  user_agent: 'curl/8',
  tool: 'curl',
  edge_nodes: ['edge-th'],
  max_stage: 'persistence',
  stages: ['recon', 'persistence'],
  categories: [],
  login_attempts: 0,
  distinct_passwords: 0,
  common_passwords: 0,
  uploads: [{ name: 'shell.php', size: 28, type: 'application/x-php', sha256: 'f'.repeat(64) }],
  tokens_issued: ['db_password'],
  tokens_replayed: ['db_password'],
  linked_from: [],
  ...over,
})

describe('honeypot stages', () => {
  it('maps every stage to a MITRE technique in order', () => {
    expect(STAGES.map((s) => STAGE_META[s].attack)).toEqual(['T1595', 'T1552', 'T1190', 'T1078', 'T1505.003'])
  })
})

describe('formatSpan', () => {
  it('reads short and long sessions', () => {
    expect(formatSpan(45)).toBe('45 วิ')
    expect(formatSpan(180, 'en')).toBe('3 min')
    expect(formatSpan(4800)).toBe('1 ชม. 20 นาที')
    expect(formatSpan(3600, 'en')).toBe('1 h')
  })
})

describe('IOC export', () => {
  it('lists IPs, file hashes and replayed tokens with Bangkok times', () => {
    const lines = iocCsv([session()]).trim().split('\r\n')
    expect(lines).toHaveLength(4)
    expect(lines[1]).toContain('"ip","198.51.100.20","abc-1800000000"')
    expect(lines[1]).toContain('"T1505.003"')
    expect(lines[2]).toContain(`"sha256","${'f'.repeat(64)}"`)
    expect(lines[3]).toContain('"honeytoken_replayed","db_password"')
    expect(lines[1]).toContain('"2026-10-28 10:00:00"')
  })
  it('never lets a cell start a spreadsheet formula', () => {
    expect(csvCell('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`)
    expect(csvCell('-1')).toBe(`"'-1"`)
    expect(iocCsv([session({ tool: '=cmd|calc', uploads: [], tokens_replayed: [] })])).toContain(`"'=cmd|calc"`)
  })
})
