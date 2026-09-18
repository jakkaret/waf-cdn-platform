import { describe, it, expect } from 'vitest'
import { parseListInput, formatListInput } from './captchaForm'

describe('parseListInput', () => {
  it('splits on newlines and trims each entry', () => {
    expect(parseListInput('/login*\n/admin*\n')).toEqual(['/login*', '/admin*'])
  })

  it('also splits on commas, for a paste from a single-line source', () => {
    expect(parseListInput('/login*, /admin*,/user/login*')).toEqual([
      '/login*',
      '/admin*',
      '/user/login*',
    ])
  })

  it('drops blank lines from trailing newlines or blank rows', () => {
    expect(parseListInput('/login*\n\n\n/admin*\n')).toEqual(['/login*', '/admin*'])
  })

  it('collapses duplicates, keeping the first occurrence', () => {
    expect(parseListInput('/login*\n/admin*\n/login*')).toEqual(['/login*', '/admin*'])
  })

  it('returns an empty array for blank input', () => {
    expect(parseListInput('   \n  \n')).toEqual([])
  })
})

describe('formatListInput', () => {
  it('joins entries with newlines for display in a textarea', () => {
    expect(formatListInput(['/login*', '/admin*'])).toBe('/login*\n/admin*')
  })

  it('round-trips through parseListInput', () => {
    const original = ['/login*', '/admin*', '/wp-login.php']
    expect(parseListInput(formatListInput(original))).toEqual(original)
  })
})
