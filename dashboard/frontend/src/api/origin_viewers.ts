import { api } from './axios'
import { OriginViewer } from '../types'

export const getOriginViewers = (originId: string) =>
  api.get<{ viewers: OriginViewer[] }>(`/origins/${originId}/viewers`)

export const addOriginViewer = (originId: string, email: string) =>
  api.post<{ status: string; viewer: OriginViewer }>(`/origins/${originId}/viewers`, { email })

export const removeOriginViewer = (originId: string, viewerId: string) =>
  api.delete<{ status: string; message: string }>(`/origins/${originId}/viewers/${viewerId}`)
