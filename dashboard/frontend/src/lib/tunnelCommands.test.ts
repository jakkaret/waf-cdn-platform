import { describe, it, expect } from 'vitest'
import { buildTunnelCommands } from './tunnelCommands'

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
