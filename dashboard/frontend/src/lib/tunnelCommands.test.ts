import { describe, it, expect } from 'vitest'
import { buildTunnelCommands, tunnelErrorMessage } from './tunnelCommands'

describe('buildTunnelCommands', () => {
  // Production change that would make this fail: the component's old inline
  // fallback fabricated a command string containing the hardcoded placeholder
  // token WAF_SECURE_TUNNEL_2026_TOKEN whenever the API returned nothing.
  it('returns null when the backend provided no config (no fabricated command)', () => {
    expect(buildTunnelCommands(undefined)).toBeNull()
    expect(buildTunnelCommands(null)).toBeNull()
    expect(buildTunnelCommands({})).toBeNull()
  })

  it('maps the top-level command fields the backend returns', () => {
    const out = buildTunnelCommands({
      linux_command: 'LINUX', docker_command: 'DOCKER', toml_config: 'TOML',
    })
    expect(out).toEqual({ linux: 'LINUX', docker: 'DOCKER', toml: 'TOML' })
  })

  it('falls back to the nested commands.* shape the backend also returns', () => {
    const out = buildTunnelCommands({
      commands: { linux_oneliner: 'L2', docker_command: 'D2', raw_toml: 'T2' },
    })
    expect(out).toEqual({ linux: 'L2', docker: 'D2', toml: 'T2' })
  })

  it('never emits the hardcoded placeholder token for any input', () => {
    const inputs = [undefined, {}, { linux_command: 'x' },
      { commands: { linux_oneliner: 'y', docker_command: 'z', raw_toml: 'w' } }]
    for (const i of inputs) {
      const out = buildTunnelCommands(i as any)
      expect(JSON.stringify(out ?? '')).not.toContain('WAF_SECURE_TUNNEL')
    }
  })
})

describe('tunnelErrorMessage', () => {
  const err = (detail: unknown) => ({ response: { status: 403, data: { detail } } })

  it('is null when there is no error', () => {
    expect(tunnelErrorMessage(null)).toBeNull()
    expect(tunnelErrorMessage(undefined)).toBeNull()
  })

  // The 403 users actually hit (log of 2026-10-25): a domain not on any origin.
  it('shows the backend reason as it is', () => {
    expect(tunnelErrorMessage(err('Add this domain to one of your origins and verify its DNS first.')))
      .toBe('Add this domain to one of your origins and verify its DNS first.')
  })

  it('turns a 422 on the domain into a hint, not a raw pydantic message', () => {
    const e = err([{ loc: ['query', 'domain'], msg: 'Value error, not a hostname' }])
    expect(tunnelErrorMessage(e)).toBe('Enter a full hostname, for example shop.example.com.')
  })

  it('reads the email gate message', () => {
    expect(tunnelErrorMessage(err({ code: 'email_unverified', message: 'ยืนยันอีเมลก่อนใช้งานส่วนนี้' })))
      .toBe('ยืนยันอีเมลก่อนใช้งานส่วนนี้')
  })

  it('says the server could not be reached for a network error', () => {
    expect(tunnelErrorMessage(new Error('Network Error'))).toBe('Could not reach the server. Try again.')
  })
})
