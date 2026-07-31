import { api } from './axios'
import { Domain, DnsInstructions, SslCert } from '../types'

export const getDomains = (originId: string) =>
  api.get<{ domains: Domain[] }>(`/origins/${originId}/domains`)

export const createDomain = (originId: string, data: { domain_name: string }) =>
  api.post<{ domain: Domain; dns_instructions: DnsInstructions }>(
    `/origins/${originId}/domains`, data
  )

export const verifyDomain = (originId: string, domainId: string) =>
  api.post<{ status: string; message: string }>(
    `/origins/${originId}/domains/${domainId}/verify`
  )

export const deleteDomain = (originId: string, domainId: string) =>
  api.delete(`/origins/${originId}/domains/${domainId}`)

export const getSslStatus = (originId: string, domainId: string) =>
  api.get<SslCert>(`/origins/${originId}/domains/${domainId}/ssl`)
