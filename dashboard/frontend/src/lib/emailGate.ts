import { create } from 'zustand'

// An account that has not confirmed the emailed code can sign in and look
// around, but the backend refuses what reaches the edge or other people
// (services/rbac.py require_verified_email): 403 with
// detail {code: 'email_unverified', action}. This file says, per action, why
// that matters, for the modal, the inline notices and the verify page.

export type GateAction = 'create_origin' | 'add_domain' | 'invite' | 'accept_invite' | 'agent_token' | 'ai' | 'link_google'

export interface GateCopy {
  title: string
  impacts: string[]
}

export const GATE_COPY: Record<GateAction, GateCopy> = {
  create_origin: {
    title: 'ยืนยันอีเมลก่อนเพิ่มเว็บ',
    impacts: [
      'traffic จริงของเว็บจะวิ่งผ่าน WAF ทุก request ถ้าตั้งผิด ผู้ใช้อาจเข้าเว็บไม่ได้',
      'ระบบจะออกใบรับรอง HTTPS ให้โดเมน และเก็บ log ของผู้เข้าเว็บ (IP, URL) ไว้ในบัญชีนี้',
      'เมื่อมีการโจมตีหรือเว็บล่ม เราต้องติดต่อเจ้าของตัวจริงได้',
    ],
  },
  add_domain: {
    title: 'ยืนยันอีเมลก่อนเพิ่มโดเมน',
    impacts: [
      'โดเมนที่เพิ่มจะถูก route ผ่าน edge และออกใบรับรอง HTTPS',
      'log ของผู้เข้าเว็บในโดเมนนี้จะอยู่ในบัญชีนี้',
    ],
  },
  invite: {
    title: 'ยืนยันอีเมลก่อนเชิญทีม',
    impacts: [
      'คนที่ถูกเชิญจะเห็น log ของผู้เข้าเว็บ และ editor แก้กฎ WAF, rate limit และ route ได้',
      'คำเชิญส่งในนามบัญชีนี้ ผู้รับต้องมั่นใจว่ามาจากเจ้าของอีเมลจริง',
      'ถ้าบัญชีถูกคนอื่นสมัครด้วยอีเมลของคุณ เขาจะเชิญคนนอกเข้ามาดูเว็บได้',
    ],
  },
  accept_invite: {
    title: 'ยืนยันอีเมลก่อนรับคำเชิญ',
    impacts: [
      'การรับคำเชิญให้สิทธิ์ดู log และ config ของเว็บคนอื่น',
      'เจ้าของเว็บต้องมั่นใจว่าบัญชีที่รับเป็นเจ้าของอีเมลจริง',
    ],
  },
  agent_token: {
    title: 'ยืนยันอีเมลก่อนสร้าง token ของ Agent',
    impacts: [
      'token เปิด tunnel จากเซิร์ฟเวอร์ของคุณเข้า edge ได้นาน 90 วัน',
      'ถ้าบัญชีไม่ใช่ของจริง token อาจถูกใช้พา traffic ที่ไม่ใช่ของคุณผ่าน WAF',
    ],
  },
  link_google: {
    title: 'ยืนยันอีเมลก่อนเชื่อม Google',
    impacts: [
      'บัญชี Google ที่เชื่อมแล้วใช้เข้าระบบแทนรหัสผ่านได้ แม้รีเซ็ตรหัสผ่านไปแล้ว',
      'ถ้าบัญชีนี้ถูกคนอื่นสมัครด้วยอีเมลของคุณ เขาจะเชื่อม Google ของเขาไว้เข้าแทนคุณได้',
    ],
  },
  ai: {
    title: 'ยืนยันอีเมลก่อนใช้ AI',
    impacts: [
      'AI ใช้โควตาที่มีค่าใช้จ่ายจริง เปิดให้เฉพาะบัญชีที่ยืนยันแล้ว เพื่อกันบัญชีปลอมใช้โควตาหมด',
      'AI อ่าน log การโจมตีของเว็บคุณ ต้องแน่ใจว่าคนถามคือเจ้าของบัญชี',
    ],
  },
}

// Why verify at all (verify page and modal footer).
export const WHY_VERIFY = [
  'กู้บัญชีได้: ลืมรหัสผ่านต้องใช้รหัสที่ส่งไปที่อีเมลนี้',
  'กันคนอื่นใช้อีเมลของคุณสมัครไว้ก่อน แล้วรอเข้าถึงเว็บที่คุณจะเพิ่ม',
  'คำเชิญทีมและการแจ้งเตือนสำคัญส่งไปที่อีเมลนี้',
]

export const LOCKED_UNTIL_VERIFIED = ['เพิ่มเว็บและโดเมน', 'เชิญหรือรับคำเชิญทีม', 'สร้าง token ของ Agent', 'ใช้ AI Copilot']
export const OPEN_BEFORE_VERIFIED = ['ดู Dashboard และหน้าต่าง ๆ', 'จัดการอุปกรณ์ที่เข้าระบบ', 'เปิด ticket ขอความช่วยเหลือ']

export const isGateAction = (value: unknown): value is GateAction =>
  typeof value === 'string' && value in GATE_COPY

// The gate's 403 from an axios error, or null for any other error.
export function parseEmailGate(error: unknown): { action: GateAction | null; message: string } | null {
  const res = (error as { response?: { status?: number; data?: { detail?: unknown } } })?.response
  const detail = res?.data?.detail as { code?: string; action?: string; message?: string } | undefined
  if (res?.status !== 403 || !detail || typeof detail !== 'object' || detail.code !== 'email_unverified') return null
  return { action: isGateAction(detail.action) ? detail.action : null, message: detail.message || 'ยืนยันอีเมลก่อนใช้งานส่วนนี้' }
}

// Six digits from whatever was typed or pasted ("123 456", "12-34-56").
export const normalizeOtp = (raw: string): string => raw.replace(/\D/g, '').slice(0, 6)

export const formatCountdown = (seconds: number): string => {
  const s = Math.max(0, Math.ceil(seconds))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

// Which gate dialog is open (opened by the axios interceptor or a guard).
interface EmailGateState {
  action: GateAction | null
  open: boolean
  show: (action: GateAction | null) => void
  close: () => void
}

export const useEmailGateStore = create<EmailGateState>((set) => ({
  action: null,
  open: false,
  show: (action) => set({ action, open: true }),
  close: () => set({ open: false }),
}))
