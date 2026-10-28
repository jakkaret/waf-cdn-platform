import { api } from './axios'

// A site's honeypot sessions (backend api/honeypot.py). Owner and editors only.

export type HoneypotStage = 'recon' | 'loot' | 'exploit' | 'credential_use' | 'persistence'

export interface HoneypotUpload {
  name: string
  size: number
  type: string
  sha256: string
}

export interface HoneypotSession {
  id: string
  actor_id: string
  first_seen: string
  last_seen: string
  duration_seconds: number
  events: number
  ips: string[]
  user_agent: string
  tool: string
  edge_nodes: string[]
  max_stage: HoneypotStage
  stages: HoneypotStage[]
  categories: string[]
  login_attempts: number
  distinct_passwords: number
  common_passwords: number
  uploads: HoneypotUpload[]
  tokens_issued: string[]
  tokens_replayed: string[]
  linked_from: string[]
}

export interface HoneypotStep {
  time: string
  request_id: string
  client_ip: string
  edge_node: string
  method: string
  path: string
  query: string
  stage: HoneypotStage
  attack_id: string
  attack_name: string
  category: string
  template: string
  tool: string
  delay_ms: number
  body_sample: string
  login: { user: string; password_length: number; common_password: boolean } | null
  upload: HoneypotUpload | null
  tokens_issued: string[]
  token_replayed: string
}

export interface HoneypotSummary {
  days: number
  sessions: number
  events: number
  unique_ips: number
  per_day: { day: string; sessions: number }[]
  max_stage: Record<HoneypotStage, number>
  reached: Record<HoneypotStage, number>
  tools: { tool: string; sessions: number }[]
}

export interface DecoyProbe {
  checked: boolean
  reason?: 'tunnel' | 'hostname' | 'not_public' | 'no_domain' | 'unreachable'
  note?: string
  path?: string
  status?: number
  baseline_status?: number | null
  serves_path?: boolean
}

const base = (originId: string) => `/api/origins/${encodeURIComponent(originId)}/honeypot`

export const getHoneypotSummary = (originId: string, days: number) =>
  api.get<HoneypotSummary>(`${base(originId)}/summary`, { params: { days } }).then((r) => r.data)

export const getHoneypotSessions = (originId: string, days: number) =>
  api.get<{ sessions: HoneypotSession[]; total: number }>(`${base(originId)}/sessions`, { params: { days } }).then((r) => r.data)

export const getHoneypotSession = (originId: string, sid: string, days: number) =>
  api
    .get<{ session: HoneypotSession & { timeline: HoneypotStep[] } }>(`${base(originId)}/sessions/${encodeURIComponent(sid)}`, { params: { days } })
    .then((r) => r.data.session)

export const getHoneypotStory = (originId: string, sid: string, days: number) =>
  api
    .post<{ story: string | null; ai: boolean }>(`${base(originId)}/sessions/${encodeURIComponent(sid)}/story`, null, { params: { days } })
    .then((r) => r.data)

export const blockHoneypotSession = (originId: string, sid: string, hours: number | null, days: number) =>
  api
    .post<{ added: string[]; skipped: { ip: string; reason: string }[] }>(
      `${base(originId)}/sessions/${encodeURIComponent(sid)}/block`,
      { hours },
      { params: { days } },
    )
    .then((r) => r.data)

export const probeDecoy = (originId: string, key: string) =>
  api.get<DecoyProbe>(`${base(originId)}/decoys/${encodeURIComponent(key)}/probe`).then((r) => r.data)
