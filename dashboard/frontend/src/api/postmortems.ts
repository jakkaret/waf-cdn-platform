import { api } from './axios'
import { Postmortem, PostmortemSummary } from '../types'

export const createPostmortem = (originId: string, startTime: string, endTime: string) =>
  api.post<{ status: string; postmortem: Postmortem }>(
    `/ai/postmortems/${originId}`,
    { start_time: startTime, end_time: endTime }
  )

export const getPostmortems = (originId: string) =>
  api.get<{ postmortems: PostmortemSummary[] }>(`/ai/postmortems/${originId}`)

export const getPostmortem = (originId: string, postmortemId: string) =>
  api.get<{ postmortem: Postmortem }>(`/ai/postmortems/${originId}/${postmortemId}`)
