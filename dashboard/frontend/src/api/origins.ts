import { api } from './axios'
import { Origin, OriginCveReport } from '../types'

export const getOrigins = (opts?: { forceRefreshStatus?: boolean }) =>
  api.get<{ origins: Origin[] }>('/origins', {
    params: opts?.forceRefreshStatus ? { refresh_status: true } : undefined,
  })

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

// Advisory: CVEs from the NVD feed matching the origin's tech stack tags.
// The first call for a new tag can take ~30 s (NVD rate limit); later calls
// are served from the backend cache.
export const getOriginCves = (id: string) =>
  api.get<OriginCveReport>(`/origins/${id}/cves`, { timeout: 60000 })
