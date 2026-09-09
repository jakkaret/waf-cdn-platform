import { api } from './axios'
import { CaptchaShieldConfig } from '../types'

export const getCaptchaConfig = (originId: string) =>
  api.get<{ origin_id: string; captcha_shield: CaptchaShieldConfig }>(
    `/origins/${originId}/captcha`
  )

export const updateCaptchaConfig = (originId: string, config: CaptchaShieldConfig) =>
  api.put<{ origin_id: string; captcha_shield: CaptchaShieldConfig }>(
    `/origins/${originId}/captcha`,
    config
  )
