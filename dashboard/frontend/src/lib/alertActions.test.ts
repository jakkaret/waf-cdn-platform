import { describe, expect, it } from 'vitest'
import { alertSeverity, isBlockableIp, logsSearchPath } from './alertActions'

describe('alertSeverity', () => {
  it('keeps a recorded severity, any case', () => {
    expect(alertSeverity('critical')).toBe('CRITICAL')
    expect(alertSeverity(' High ')).toBe('HIGH')
  })

  it('does not invent one from nothing', () => {
    expect(alertSeverity(null)).toBeNull()
    expect(alertSeverity('')).toBeNull()
    expect(alertSeverity('403')).toBeNull()
  })
})

describe('isBlockableIp', () => {
  it('accepts IPv4 and IPv6 addresses', () => {
    expect(isBlockableIp('64.227.32.66')).toBe(true)
    expect(isBlockableIp('2001:db8::1')).toBe(true)
  })

  it('rejects anything else', () => {
    expect(isBlockableIp('')).toBe(false)
    expect(isBlockableIp('unknown')).toBe(false)
    expect(isBlockableIp('256.1.1.1')).toBe(false)
    expect(isBlockableIp('example.com')).toBe(false)
  })
})

describe('logsSearchPath', () => {
  it('encodes the query', () => {
    expect(logsSearchPath('1.2.3.4')).toBe('/logs?search=1.2.3.4')
    expect(logsSearchPath('a b')).toBe('/logs?search=a+b')
  })
})
