import { api } from './axios'
import { OtpShieldConfig } from '../types'

export const getOtpConfig = (originId: string) =>
  api.get<{ origin_id: string; otp_shield: OtpShieldConfig }>(`/origins/${originId}/otp`)

export const updateOtpConfig = (originId: string, config: OtpShieldConfig) =>
  api.put<{ origin_id: string; otp_shield: OtpShieldConfig }>(`/origins/${originId}/otp`, config)
