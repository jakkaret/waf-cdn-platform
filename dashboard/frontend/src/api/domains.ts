import { api } from './axios'
import { Domain, DnsInstructions, SslCert } from '../types'

export const getDomains = (originId: string) =>
  api.get<{ domains: Domain[] }>(`/api/origins/${originId}/domains`)

export const createDomain = (originId: string, data: { domain_name: string }) =>
  api.post<{ domain: Domain; dns_instructions: DnsInstructions }>(
    `/api/origins/${originId}/domains`, data
  )

export const verifyDomain = (originId: string, domainId: string) =>
  api.post<{ status: string; message: string }>(
    `/api/origins/${originId}/domains/${domainId}/verify`
  )

export const deleteDomain = (originId: string, domainId: string) =>
  api.delete(`/api/origins/${originId}/domains/${domainId}`)

export const getSslStatus = (originId: string, domainId: string) =>
  api.get<SslCert>(`/api/origins/${originId}/domains/${domainId}/ssl`)
