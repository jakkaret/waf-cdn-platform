import { api } from './axios'

// --- Per-origin rules (api/tenant_rules.py) -------------------------------

export interface TenantRule {
  id: number
  origin_id: string
  variable: string
  operator: string // "@contains /admin" -- operator and its value in one string
  message: string
  action: 'BLOCK' | 'CHALLENGE' | 'DECEIVE' | 'LOG'
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  deception_template: string
  enabled: boolean
  created_by?: string
  created_at?: string
  decoy?: string // set when this rule came from a decoy-path toggle, not the rule builder
}

export type TenantRuleInput = Omit<TenantRule, 'id' | 'origin_id' | 'created_by' | 'created_at' | 'decoy'>

export interface TenantRuleOptions {
  variables: Record<string, string> // variable -> human label
  operators: string[]
  actions: string[]
  severities: string[]
  deception_templates: string[]
  max_rules_per_origin: number
}

export const getTenantRuleOptions = (originId: string) =>
  api.get<TenantRuleOptions>(`/origins/${originId}/waf-rules/options`)

export const getTenantRules = (originId: string) =>
  api.get<{ rules: TenantRule[] }>(`/origins/${originId}/waf-rules/`)

export const createTenantRule = (originId: string, rule: TenantRuleInput) =>
  api.post<TenantRule>(`/origins/${originId}/waf-rules/`, rule)

export const updateTenantRule = (originId: string, ruleId: number, rule: TenantRuleInput) =>
  api.put<TenantRule>(`/origins/${originId}/waf-rules/${ruleId}`, rule)

export const deleteTenantRule = (originId: string, ruleId: number) =>
  api.delete<{ message: string }>(`/origins/${originId}/waf-rules/${ruleId}`)

// --- Decoy paths (one-click DECEIVE for common bot-probed URLs) ------------

export interface Decoy {
  key: string
  path: string
  label: string
  enabled: boolean
  rule_id: number | null
}

export const getDecoys = (originId: string) =>
  api.get<{ decoys: Decoy[] }>(`/origins/${originId}/waf-rules/decoys`)

export const setDecoy = (originId: string, key: string, enabled: boolean) =>
  api.put<{ key: string; enabled: boolean }>(`/origins/${originId}/waf-rules/decoys/${key}`, { enabled })

// --- Central managed ruleset (api/managed_rules.py) -----------------------

export interface ManagedVersion {
  version: number
  published_at: string
  added: number[]
  retired: number[]
}

export interface ManagedRuleRow {
  id: number
  message: string
  severity: string
  introduced_in: number
  retired_in: number | null
  active: boolean
}

export interface ManagedStatus {
  mode: 'auto' | 'manual'
  current_version: number
  latest_version: number
  update_available: boolean
  versions: ManagedVersion[]
  rules: ManagedRuleRow[]
}

export const getManagedStatus = (originId: string) =>
  api.get<ManagedStatus>(`/managed-rules/origins/${originId}/status`)

export const setManagedMode = (originId: string, mode: 'auto' | 'manual', version?: number) =>
  api.put<ManagedStatus>(`/managed-rules/origins/${originId}/mode`, { mode, version })

export const updateManagedToLatest = (originId: string) =>
  api.post<ManagedStatus>(`/managed-rules/origins/${originId}/update`)
