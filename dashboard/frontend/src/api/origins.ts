import { api } from './axios'

export interface Origin {
  id: string
  label: string
  ip: string
  port: number
  status: 'pending' | 'active' | 'down'
  created_at: string
  updated_at: string
}

export const getOrigins = async (): Promise<Origin[]> => {
  const { data } = await api.get('/origins')
  return data
}

export const getOrigin = async (id: string): Promise<Origin> => {
  const { data } = await api.get(`/origins/${id}`)
  return data
}

export const createOrigin = async (originData: Omit<Origin, 'id' | 'status' | 'created_at' | 'updated_at'>): Promise<Origin> => {
  const { data } = await api.post('/origins', originData)
  return data
}

export const updateOrigin = async (id: string, originData: Partial<Omit<Origin, 'id' | 'created_at' | 'updated_at'>>): Promise<Origin> => {
  const { data } = await api.put(`/origins/${id}`, originData)
  return data
}

export const deleteOrigin = async (id: string): Promise<void> => {
  await api.delete(`/origins/${id}`)
}
