import { api } from './axios'
import { Origin } from '../types'

export const getOrigins = () => api.get<{ origins: Origin[] }>('/api/origins')

export const createOrigin = (data: { ip: string; port: number; label: string }) =>
  api.post<Origin>('/api/origins', data)

export const updateOrigin = (id: string, data: Partial<Origin>) =>
  api.put<Origin>(`/api/origins/${id}`, data)

export const deleteOrigin = (id: string) =>
  api.delete(`/api/origins/${id}`)

export const getOrigin = (id: string) =>
  api.get<Origin>(`/api/origins/${id}`)
