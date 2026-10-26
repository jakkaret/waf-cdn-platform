import { api } from './axios'
import { DnsInstructions, OriginAdjusted } from '../types'

export type ConnectionMode = 'direct' | 'agent'

// POST /api/onboarding/inspect -- see services/site_connect.py
export interface InspectResult {
  domain: string
  already_registered: boolean
  cname_target?: string
  current?: { cname: string; a: string[] }
  already_points_to_platform?: boolean
  cdn?: string | null
  origin?: { ip: string; port: number; scheme: 'http' | 'https'; status: number } | null
  recommended_mode?: ConnectionMode
  reason?: 'reachable' | 'unreachable' | 'behind_cdn' | 'already_on_platform' | 'private_address' | 'no_address'
}

export interface ConnectRequest {
  domain: string
  mode: ConnectionMode
  port: number
  origin_address?: string
  scheme?: 'http' | 'https'
}

export interface ConnectResult {
  origin_id: string
  connection_mode: ConnectionMode
  verified: boolean
  dns_instructions: DnsInstructions | null
  origin_adjusted?: OriginAdjusted | null
}

export type ConnectionStatus = 'connected' | 'waiting_agent' | 'waiting_dns' | 'configuring' | 'error' | 'unknown'

// What the platform sees for a pending domain. `via` is where the CNAME came
// from: the domain's own nameservers (fresh) or the resolver (may be a cached,
// older answer). cname_ok / txt_ok: that record already matches.
export interface CurrentDns {
  cname: string
  a: string[]
  via?: 'authoritative' | 'resolver'
  nameserver?: string
  cname_ok?: boolean
  txt_ok?: boolean
  // false: the name still sends visitors somewhere else (a live site)
  points_here?: boolean
}

export interface ProgressDomain {
  domain_id: string
  domain_name: string
  created_at?: string
  dns: {
    status: 'verified' | 'pending'
    current: CurrentDns | null
    instructions: DnsInstructions
  }
  connection: { status: ConnectionStatus }
  https: {
    status: 'none' | 'pending' | 'active' | 'error'
    issuer?: string | null
    days_remaining?: number | null
    expires_at?: string | null
  }
  ready: boolean
}

export interface OriginProgress {
  origin_id: string
  origin_status: string
  // false for read-only members: no verification token, no side effects
  can_edit: boolean
  // owner or platform admin: may mint the agent install command
  can_mint_agent: boolean
  connection_mode: ConnectionMode | null
  origin_egress_ips: string[]
  origin_address: string
  origin_port: number
  origin_scheme: 'http' | 'https' | null
  domains: ProgressDomain[]
  all_ready: boolean
}

export const onboardingApi = {
  inspect: async (domain: string): Promise<InspectResult> => {
    const res = await api.post<InspectResult>('/onboarding/inspect', { domain })
    return res.data
  },
  connect: async (body: ConnectRequest): Promise<ConnectResult> => {
    const res = await api.post<ConnectResult>('/onboarding/connect', body)
    return res.data
  },
  progress: async (originId: string): Promise<OriginProgress> => {
    const res = await api.get<OriginProgress>(`/onboarding/progress/${originId}`)
    return res.data
  },
}
