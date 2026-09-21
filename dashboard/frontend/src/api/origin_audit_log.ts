import { api } from './axios'
import { AuditEvent } from '../types'

export const getOriginAuditLog = (originId: string) =>
  api.get<{ events: AuditEvent[] }>(`/origins/${originId}/audit-log`)
