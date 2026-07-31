import { api } from './axios'
import { Origin } from '../types'

export const getOrigins = () => api.get<{ origins: Origin[] }>('/origins')

export const createOrigin = (data: { ip: string; port: number; label: string }) =>
  api.post<Origin>('/origins', data)

export const updateOrigin = (id: string, data: Partial<Origin>) =>
  api.put<Origin>(`/origins/${id}`, data)

export const deleteOrigin = (id: string) =>
  api.delete(`/origins/${id}`)

export const getOrigin = (id: string) =>
  api.get<Origin>(`/origins/${id}`)

export const restoreOrigin = (id: string) =>
  api.post<{ status: string; message: string }>(`/origins/${id}/restore`)
