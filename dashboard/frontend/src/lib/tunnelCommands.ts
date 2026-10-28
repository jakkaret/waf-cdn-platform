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

// Why the backend refused to mint a config, as one line for the command box.
// The page used to swallow this error and keep showing its placeholder, so a
// domain the user did not own looked like a page that did nothing. detail is
// a string from our own HTTPExceptions, a list from FastAPI's 422 validation,
// or {message} from the email gate.
export function tunnelErrorMessage(error: unknown, lang: 'en' | 'th' = 'en'): string | null {
  if (!error) return null
  const th = lang === 'th'
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string' && detail) return detail
  if (Array.isArray(detail) && detail.length) {
    const first = detail[0] as { loc?: unknown[]; msg?: string }
    const field = Array.isArray(first?.loc) ? first.loc[first.loc.length - 1] : null
    if (field === 'domain') return th ? 'กรอกชื่อ host เต็ม เช่น shop.example.com' : 'Enter a full hostname, for example shop.example.com.'
    if (field === 'port') return th ? 'Local port ต้องเป็นตัวเลขตั้งแต่ 1 ถึง 65535' : 'Local port must be a number from 1 to 65535.'
    return first?.msg || (th ? 'คำขอไม่ถูกต้อง' : 'The request was not valid.')
  }
  if (detail && typeof detail === 'object' && typeof (detail as { message?: unknown }).message === 'string') {
    return (detail as { message: string }).message
  }
  return th ? 'ติดต่อเซิร์ฟเวอร์ไม่ได้ ลองใหม่อีกครั้ง' : 'Could not reach the server. Try again.'
}
