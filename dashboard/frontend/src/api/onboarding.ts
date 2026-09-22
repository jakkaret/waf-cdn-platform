import { api } from './axios'

export type OnboardingStep = 'create_origin' | 'add_domain' | 'verify_domain' | 'done'

export interface OnboardingStatus {
  has_origin: boolean
  origin_count: number
  domain_configured: boolean
  domain_verified: boolean
  next_step: OnboardingStep
  onboarding_complete: boolean
  // 2026-09-22: lets the resume effect restore originId/domainId/
  // domainName, not just the step number -- see Onboarding.tsx.
  resume_origin_id: string | null
  resume_domain_id: string | null
  resume_domain_name: string | null
}

export const onboardingApi = {
  getStatus: async (): Promise<OnboardingStatus> => {
    const res = await api.get<OnboardingStatus>('/onboarding/status')
    return res.data
  },
}
