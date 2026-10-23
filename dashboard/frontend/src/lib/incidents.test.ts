import { describe, it, expect } from 'vitest'
import { attackTypeLabel, incidentMinutes, incidentSite, incidentTypes, incidentWhen } from './incidents'

const inc = {
  scope: 'o1', label: 'shop', opened_at: '2026-10-23T06:09:00Z', last_seen_at: '2026-10-23T06:13:20Z',
  top_types: [['Restricted File Access Attempt', 300], ['Something New', 15]] as [string, number][],
}

describe('incidents', () => {
  it('words the site, unattributed traffic included', () => {
    expect(incidentSite(inc)).toBe('shop')
    expect(incidentSite({ scope: 'unattributed', label: null })).toBe('traffic ที่ไม่ตรงกับเว็บไหน')
  })
  it('translates known attack types and keeps unknown ones', () => {
    expect(attackTypeLabel('Restricted File Access Attempt')).toBe('พยายามเปิดไฟล์ต้องห้าม')
    expect(incidentTypes(inc)).toBe('พยายามเปิดไฟล์ต้องห้าม, Something New')
  })
  it('rounds the duration up and shows Bangkok time', () => {
    expect(incidentMinutes(inc)).toBe(5)
    expect(incidentWhen(inc)).toMatch(/13:09–13:13$/)
  })
})
