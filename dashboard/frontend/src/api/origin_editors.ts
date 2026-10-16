import { api } from './axios'
import { OriginEditor } from '../types'

export const getOriginEditors = (originId: string) =>
  api.get<{ editors: OriginEditor[] }>(`/origins/${originId}/editors`)

export const addOriginEditor = (originId: string, email: string) =>
  api.post<{ status: 'invited'; email: string; role: 'viewer' | 'editor'; email_sent: boolean }>(`/origins/${originId}/editors`, { email })

export const removeOriginEditor = (originId: string, editorId: string) =>
  api.delete<{ status: string; message: string }>(`/origins/${originId}/editors/${editorId}`)
