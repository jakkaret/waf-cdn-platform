// One status vocabulary and one set of protection states for the Origins
// list, the origin header and the Protection tab, all from real fields:
// the origin record (status, tunnel connectivity) and GET
// /api/origins/overview (services/origin_overview.py). Nothing here guesses
// or suggests; a value the backend could not read shows as unknown.

import type { Origin, OriginOverview } from '../types'
import type { Lang } from '../i18n'
import type { OriginTabId } from '../components/layout/navigation'

export type Tone = 'ok' | 'warn' | 'bad' | 'off'

export type HealthId = 'archived' | 'pending' | 'tunnel_offline' | 'offline' | 'inactive' | 'pending_dns' | 'online'

export interface Health {
  // Stable id; label is in the viewer's language.
  id: HealthId
  label: string
  tone: Tone
  // Lower sorts first in "Needs action".
  rank: number
  needsAction: boolean
  step?: { label: string; tab?: OriginTabId; path?: string }
}

export function originHealth(o: Pick<Origin, 'status' | 'is_tunnel' | 'live_connected' | 'health'>, domains?: OriginOverview['domains'], lang: Lang = 'en'): Health {
  const t = (en: string, th: string) => (lang === 'th' ? th : en)
  if (o.status === 'archived') return { label: t('Archived', 'เก็บถาวร'), id: 'archived', tone: 'off', rank: 9, needsAction: false }
  if (o.status === 'pending') {
    return { label: t('Pending setup', 'รอตั้งค่า'), id: 'pending', tone: 'warn', rank: 1, needsAction: true, step: { label: t('Finish the domain setup', 'ตั้งค่าโดเมนให้เสร็จ'), tab: 'domains' } }
  }
  if (o.is_tunnel && o.live_connected === false) {
    return { label: t('Tunnel offline', 'Tunnel ออฟไลน์'), id: 'tunnel_offline', tone: 'bad', rank: 0, needsAction: true, step: { label: t('Check the tunnel agent', 'ตรวจ tunnel agent'), path: '/tunnels' } }
  }
  if (o.status === 'error' || o.health === 'down') {
    return { label: t('Offline', 'ออฟไลน์'), id: 'offline', tone: 'bad', rank: 0, needsAction: true, step: { label: t('Check your server', 'ตรวจเซิร์ฟเวอร์ของคุณ'), tab: 'overview' } }
  }
  if (o.status === 'inactive') {
    return { label: t('Inactive', 'ไม่ได้ใช้งาน'), id: 'inactive', tone: 'warn', rank: 2, needsAction: true, step: { label: t('Check the origin settings', 'ตรวจการตั้งค่า origin'), tab: 'overview' } }
  }
  if (!o.is_tunnel && domains && domains.total > 0 && domains.verified === 0) {
    return { label: t('Pending DNS', 'รอ DNS'), id: 'pending_dns', tone: 'warn', rank: 1, needsAction: true, step: { label: t('Point DNS to the edge', 'ชี้ DNS มาที่ edge'), tab: 'domains' } }
  }
  return { label: t('Online', 'ออนไลน์'), id: 'online', tone: 'ok', rank: 5, needsAction: false }
}

export type ProtKey = 'waf' | 'ml' | 'ip' | 'rate' | 'shield'
export const PROT_KEYS: ProtKey[] = ['waf', 'ml', 'ip', 'rate', 'shield']

// The old tab each protection lives in, so links and quick search keep working.
export const PROT_TAB: Record<ProtKey, OriginTabId> = {
  waf: 'waf',
  ml: 'ml',
  ip: 'ip-access',
  rate: 'rate-limits',
  shield: 'shield',
}

export const PROT_META: Record<ProtKey, { name: string; tech: string; desc: string }> = {
  waf: { name: 'Attack rules', tech: 'WAF · OWASP CRS', desc: 'Blocks SQL injection, cross-site scripting and other known attack patterns. Always on.' },
  ml: { name: 'AI blocking', tech: 'ML risk score', desc: 'Scores every request 0–100; in enforce mode high scores are challenged or blocked.' },
  ip: { name: 'IP rules', tech: 'IP access', desc: 'Block an address or range, or always let a trusted one through.' },
  rate: { name: 'Rate limits', tech: 'Request floods', desc: 'Caps how many requests one visitor can send to a path in a time window.' },
  shield: { name: 'Login protection', tech: 'Bot & login shield', desc: 'A CAPTCHA or an email code before someone reaches a login page.' },
}

export const PROT_META_TH: Record<ProtKey, { name: string; tech: string; desc: string }> = {
  waf: { name: 'กฎกันการโจมตี', tech: 'WAF · OWASP CRS', desc: 'บล็อก SQL injection, cross-site scripting และรูปแบบการโจมตีที่รู้จักอื่น ๆ เปิดตลอด' },
  ml: { name: 'บล็อกด้วย AI', tech: 'ML risk score', desc: 'ให้คะแนนทุก request 0–100 ในโหมด enforce คะแนนสูงจะถูก challenge หรือบล็อก' },
  ip: { name: 'กฎ IP', tech: 'IP access', desc: 'บล็อก IP หรือช่วง IP หรืออนุญาต IP ที่เชื่อถือได้ให้ผ่านเสมอ' },
  rate: { name: 'Rate limit', tech: 'Request floods', desc: 'จำกัดจำนวน request ที่ผู้เข้าชมหนึ่งคนส่งไปยัง path ได้ในช่วงเวลาหนึ่ง' },
  shield: { name: 'ป้องกันการล็อกอิน', tech: 'Bot & login shield', desc: 'ให้ทำ CAPTCHA หรือกรอกรหัสทางอีเมลก่อนเข้าหน้าล็อกอิน' },
}

export const protMeta = (k: ProtKey, lang: Lang = 'en') => (lang === 'th' ? PROT_META_TH : PROT_META)[k]

export type ProtState = 'on' | 'watch' | 'off' | 'unknown'
export const PROT_STATE_LABEL: Record<ProtState, string> = { on: 'On', watch: 'Watching', off: 'Off', unknown: 'Unknown' }
export const PROT_STATE_LABEL_TH: Record<ProtState, string> = { on: 'เปิด', watch: 'เฝ้าดู', off: 'ปิด', unknown: 'ไม่ทราบ' }

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

export function protectionStates(p: OriginOverview['protection'] | null | undefined, lang: Lang = 'en'): Record<ProtKey, { state: ProtState; summary: string }> {
  const th = lang === 'th'
  // Thai has no plural form: "2 กฎ".
  const count = (n: number, one: string, many: string | undefined, thWord: string) => (th ? `${n} ${thWord}` : plural(n, one, many))
  const waf = p?.waf
  const ml = p?.ml
  const ip = p?.ip
  const rate = p?.rate
  const shield = p?.shield
  const shieldParts = [shield?.captcha ? 'CAPTCHA' : '', shield?.otp ? (th ? 'รหัสทางอีเมล' : 'Email code') : ''].filter(Boolean)
  return {
    // CRS runs for every origin; the summary is the owner's additions.
    waf: {
      state: 'on',
      summary:
        waf && waf.custom_rules !== null && waf.decoys !== null
          ? `${count(waf.custom_rules, 'own rule', undefined, 'กฎของคุณ')} · ${count(waf.decoys, 'trap path', undefined, 'path กับดัก')}`
          : 'OWASP CRS',
    },
    ml: !ml
      ? { state: 'unknown', summary: '—' }
      : ml.mode === 'enforce'
      ? { state: 'on', summary: th ? `บล็อกตั้งแต่ ${ml.block_score}` : `Blocks from ${ml.block_score}` }
      : { state: 'watch', summary: th ? 'เฝ้าดูอย่างเดียว' : 'Watching only' },
    ip: !ip
      ? { state: 'unknown', summary: '—' }
      : ip.block + ip.allow > 0
      ? { state: 'on', summary: [ip.block ? (th ? `บล็อก ${ip.block}` : `${ip.block} blocked`) : '', ip.allow ? (th ? `อนุญาต ${ip.allow}` : `${ip.allow} allowed`) : ''].filter(Boolean).join(' · ') }
      : { state: 'off', summary: th ? 'ไม่มีกฎ' : 'No rules' },
    rate: !rate
      ? { state: 'unknown', summary: '—' }
      : rate.enabled > 0
      ? { state: 'on', summary: count(rate.enabled, 'limit', undefined, 'limit') }
      : { state: 'off', summary: rate.rules ? (th ? `${rate.rules} limit หยุดไว้` : `${plural(rate.rules, 'limit')} paused`) : th ? 'ไม่มี limit' : 'No limits' },
    shield:
      !shield || (shield.captcha === null && shield.otp === null)
        ? { state: 'unknown', summary: '—' }
        : shieldParts.length
        ? { state: 'on', summary: shieldParts.join(' + ') }
        : { state: 'off', summary: th ? 'ไม่ได้ใช้' : 'Not used' },
  }
}

export const onCount = (s: Record<ProtKey, { state: ProtState }>) => PROT_KEYS.filter((k) => s[k].state === 'on').length
