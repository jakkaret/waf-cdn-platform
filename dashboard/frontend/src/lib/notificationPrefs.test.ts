import { describe, it, expect } from 'vitest'
import { sensitivityHint, visibleKinds } from './notificationPrefs'

const levels = { low: { total: 200, per_ip: 100 }, medium: { total: 50, per_ip: 30 }, high: { total: 20, per_ip: 10 } }

describe('notificationPrefs', () => {
  it('words the thresholds of a level', () => {
    expect(sensitivityHint('medium', levels)).toBe('แจ้งเมื่อบล็อก ≥ 50 ครั้งใน 5 นาที หรือ IP เดียว ≥ 30 ครั้ง')
  })
  it('hides team changes from people who cannot receive them', () => {
    const viewer = { changeable: ['attacks', 'outages', 'certs', 'digest'] as const, prefs: { attacks: true, outages: false, certs: false, team: false, digest: false } }
    expect(visibleKinds({ ...viewer, changeable: [...viewer.changeable] }).map((k) => k.kind)).toEqual(['attacks', 'outages', 'certs', 'digest'])
  })
})
