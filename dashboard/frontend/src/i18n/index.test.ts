import { describe, expect, it } from 'vitest'
import { severityLabel, statusWord, tr, useLangStore } from './index'

describe('i18n helpers', () => {
  it('picks the string of the current language', () => {
    useLangStore.getState().setLang('en')
    expect(tr('Save', 'บันทึก')).toBe('Save')
    useLangStore.getState().setLang('th')
    expect(tr('Save', 'บันทึก')).toBe('บันทึก')
  })

  it('labels severities in both languages', () => {
    expect(severityLabel('CRITICAL', 'en')).toBe('Critical')
    expect(severityLabel('high', 'th')).toBe('สูง')
    expect(severityLabel('weird', 'th')).toBe('weird')
  })

  it('translates status words and keeps a leading emoji', () => {
    expect(statusWord('🟢 ONLINE', 'th')).toBe('🟢 ออนไลน์')
    expect(statusWord('TUNNEL DISCONNECTED', 'th')).toBe('Tunnel ไม่ได้เชื่อมต่อ')
    expect(statusWord('ACTIVE', 'en')).toBe('ACTIVE')
    expect(statusWord('SOMETHING ELSE', 'th')).toBe('SOMETHING ELSE')
  })
})
