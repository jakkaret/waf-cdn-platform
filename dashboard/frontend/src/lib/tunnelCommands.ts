// Pure helper extracted from Tunnels.tsx.
//
// A tunnel install command embeds a JWT that only the backend can mint (scoped
// to a domain the caller owns). The UI must therefore show ONLY what the
// backend returned: it must never fabricate a command from a client-side
// template, which is how the old inline fallback ended up printing a hardcoded
// placeholder token (WAF_SECURE_TUNNEL_2026_TOKEN) and an unscoped frpc config.
// When the backend has not returned a config, there is no command to show.

export interface TunnelConfigResponse {
  linux_command?: string
  docker_command?: string
  toml_config?: string
  commands?: {
    linux_oneliner?: string
    docker_command?: string
    raw_toml?: string
  }
}

export interface TunnelCommands {
  linux: string
  docker: string
  toml: string
}

export function buildTunnelCommands(
  config: TunnelConfigResponse | null | undefined
): TunnelCommands | null {
  if (!config) return null
  const linux = config.linux_command ?? config.commands?.linux_oneliner
  const docker = config.docker_command ?? config.commands?.docker_command
  const toml = config.toml_config ?? config.commands?.raw_toml
  // All three come from one backend response; if the linux command is absent
  // the backend did not mint anything, so there is nothing safe to display.
  if (!linux) return null
  return { linux, docker: docker ?? '', toml: toml ?? '' }
}
