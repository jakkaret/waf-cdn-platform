import { describe, expect, it } from 'vitest'
import { bandError, bandRange, bands, isDirty, share } from './mlProtection'

describe('bandError', () => {
  it('accepts the suggested bands and a block-only setting', () => {
    expect(bandError(88, 95)).toBeNull()
    expect(bandError(null, 97)).toBeNull()
    expect(bandError(50, 51)).toBeNull()
  })

  it('refuses what the backend refuses', () => {
    expect(bandError(95, 95)).toMatch(/lower than/)
    expect(bandError(96, 95)).toMatch(/lower than/)
    expect(bandError(49, 95)).toMatch(/Challenge score/)
    expect(bandError(88, 101)).toMatch(/Block score/)
    expect(bandError(88, 50)).toMatch(/Block score/)
    expect(bandError(88.5, 95)).toMatch(/whole number/)
    expect(bandError(88, Number.NaN)).toMatch(/Block score/)
  })
})

describe('bands', () => {
  it('splits 0-100 into allowed, challenge and block', () => {
    const b = bands(88, 95)
    expect(b.map((x) => [x.key, x.from, x.to])).toEqual([['pass', 0, 88], ['challenge', 88, 95], ['block', 95, 100]])
    expect(b.map(bandRange)).toEqual(['0-87', '88-94', '95-100'])
  })

  it('has no challenge band when it is off', () => {
    expect(bands(null, 97).map((x) => x.key)).toEqual(['pass', 'block'])
    expect(bandRange(bands(null, 100)[1])).toBe('100')
  })
})

describe('share and isDirty', () => {
  it('formats shares', () => {
    expect(share(0, 10)).toBe('0%')
    expect(share(1, 2000)).toBe('<0.1%')
    expect(share(3, 100)).toBe('3.0%')
    expect(share(25, 100)).toBe('25%')
  })

  it('compares the form with what is saved', () => {
    const saved = { mode: 'log', challenge_score: 88, block_score: 95 }
    expect(isDirty(saved, { ...saved })).toBe(false)
    expect(isDirty(saved, { ...saved, mode: 'enforce' })).toBe(true)
    expect(isDirty(saved, { ...saved, challenge_score: null })).toBe(true)
  })
})
