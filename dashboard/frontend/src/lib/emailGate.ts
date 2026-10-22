import { create } from 'zustand'

// An account that has not confirmed the emailed code can sign in and look
// around, but the backend refuses what reaches the edge or other people
// (services/rbac.py require_verified_email): 403 with
// detail {code: 'email_unverified', action}. This file says, per action, why
// that matters, for the modal, the inline notices and the verify page.

export type GateAction = 'create_origin' | 'add_domain' | 'invite' | 'accept_invite' | 'agent_token' | 'ai' | 'link_google'

// How loud the dialog is. 'caution': the action changes how a live site is
// served or who can see it, so the dialog lists what it does in an amber box.
// 'info': nothing reaches the site or other people beyond this account, so one
// calm line is enough. Either way the copy speaks to the address owner (the
// usual reader), never as if they were the suspect.
export type GateLevel = 'caution' | 'info'

export interface GateCopy {
  title: string
  level: GateLevel
  reasons: string[]
}

export const GATE_COPY: Record<GateAction, GateCopy> = {
  create_origin: {
    title: 'ยืนยันอีเมลก่อนเพิ่มเว็บ',
    level: 'caution',
    reasons: [
      'traffic ของเว็บจะวิ่งผ่าน WAF และระบบจะเก็บ log ผู้เข้าเว็บ (IP, URL) ไว้ในบัญชีนี้',
      'อีเมลนี้จะเป็นช่องทางกู้บัญชีและติดต่อเจ้าของเว็บ จึงต้องแน่ใจว่าใช้ได้จริง',
    ],
  },
  add_domain: {
    title: 'ยืนยันอีเมลก่อนเพิ่มโดเมน',
    level: 'caution',
    reasons: ['ระบบจะออกใบรับรอง HTTPS ให้โดเมนนี้ และเก็บ log ผู้เข้าเว็บไว้ในบัญชีนี้'],
  },
  invite: {
    title: 'ยืนยันอีเมลก่อนเชิญทีม',
    level: 'caution',
    reasons: [
      'สมาชิกที่เชิญจะเห็น log ผู้เข้าเว็บ ส่วน editor แก้กฎ WAF, rate limit และ route ได้',
      'คำเชิญส่งในชื่ออีเมลนี้ ผู้รับจึงควรรู้แน่ว่ามาจากคุณ',
    ],
  },
  agent_token: {
    title: 'ยืนยันอีเมลก่อนสร้าง token ของ Agent',
    level: 'caution',
    reasons: ['token นี้เชื่อมเซิร์ฟเวอร์ของคุณเข้า edge ได้ 90 วัน เก็บไว้เหมือนรหัสผ่าน'],
  },
  accept_invite: {
    title: 'ยืนยันอีเมลเพื่อรับคำเชิญ',
    level: 'info',
    reasons: ['คำเชิญส่งถึงอีเมลนี้ ยืนยันแล้วเจ้าของเว็บจะมั่นใจว่าคนที่เข้าร่วมคือคุณ'],
  },
  link_google: {
    title: 'ยืนยันอีเมลเพื่อเชื่อม Google',
    level: 'info',
    reasons: ['เชื่อมแล้วเข้าระบบด้วย Google แทนรหัสผ่านได้ จึงต้องยืนยันก่อนว่าบัญชีนี้เป็นของคุณ'],
  },
  ai: {
    title: 'ยืนยันอีเมลเพื่อใช้ AI',
    level: 'info',
    reasons: ['AI อ่าน log การโจมตีของเว็บคุณและมีโควตาต่อบัญชี จึงเปิดให้บัญชีที่ยืนยันอีเมลแล้ว'],
  },
}

// Why verify at all (verify page).
export const WHY_VERIFY = [
  'ใช้กู้บัญชีเมื่อลืมรหัสผ่าน',
  'ยืนยันว่าอีเมลนี้เป็นของคุณ ไม่มีใครใช้อีเมลของคุณสมัครแทนได้',
  'คำเชิญทีมจะส่งมาที่อีเมลนี้',
]

export const LOCKED_UNTIL_VERIFIED = ['เพิ่มเว็บและโดเมน', 'เชิญหรือรับคำเชิญทีม', 'สร้าง token ของ Agent', 'ใช้ AI Copilot', 'เชื่อมบัญชี Google']
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
