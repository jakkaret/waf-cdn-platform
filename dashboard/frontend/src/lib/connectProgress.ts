// Pure helpers behind ConnectSiteFlow and DomainStatusCard: what to show for
// an /api/onboarding/inspect result and for each /progress check. Kept out of
// the components so every branch is unit-tested.
import type { InspectResult, ProgressDomain, ConnectionMode, CurrentDns } from '../api/onboarding'

// People paste the site's address as they see it in the browser
// ("https://shop.example.com/", with a path or port); keep only the hostname.
// Anything that still is not a hostname is left for the form's validator.
export function normalizeDomainInput(raw: string): string {
  let s = raw.trim().toLowerCase()
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^\/\//, '')
  s = s.split(/[/?#]/)[0]
  s = s.slice(s.lastIndexOf('@') + 1)
  return s.replace(/:\d*$/, '').replace(/\.$/, '')
}

export type CheckState = 'done' | 'waiting' | 'blocked' | 'neutral'

export interface CheckView {
  state: CheckState
  label: string
  detail: string
}

// The name still sends visitors to another host: a site that is already
// live. Such a site is verified by TXT first and its CNAME moved after, so
// visitors never reach the edge before it can issue the certificate.
export function liveElsewhere(d: ProgressDomain): boolean {
  const cur = d.dns.current
  return !!cur && cur.points_here === false && (!!cur.cname || (cur.a?.length ?? 0) > 0)
}

function pointsAt(cur: CurrentDns): string {
  return cur.cname || cur.a.join(', ')
}

export function dnsCheck(d: ProgressDomain): CheckView {
  const cur = d.dns.current
  const want = d.dns.instructions.cname_record.value
  if (d.dns.status === 'verified') {
    if (cur && liveElsewhere(d)) {
      return {
        state: 'waiting',
        label: 'DNS',
        detail: `ยืนยันโดเมนแล้ว · ขั้นที่ 2 แก้ CNAME ให้ชี้มาที่ ${want} (ตอนนี้ยังชี้ไปที่ ${pointsAt(cur)})`,
      }
    }
    return { state: 'done', label: 'DNS', detail: `ชี้มาที่ ${want} แล้ว` }
  }
  if (cur?.cname_ok || cur?.txt_ok) {
    const which = cur.cname_ok ? 'CNAME' : 'TXT'
    return { state: 'waiting', label: 'DNS', detail: `${which} ถูกต้องแล้ว กำลังยืนยัน (ไม่เกิน 1 นาที)` }
  }
  if (cur && liveElsewhere(d)) {
    return {
      state: 'waiting',
      label: 'DNS',
      detail: `เว็บนี้ใช้งานอยู่ (ตอนนี้ชี้ไปที่ ${pointsAt(cur)}) · ขั้นที่ 1 เพิ่ม TXT ด้านล่างก่อน ยืนยันแล้วค่อยแก้ CNAME เว็บจะไม่สะดุด${dnsSource(cur)}`,
    }
  }
  let now = 'ยังไม่พบ record'
  if (cur?.cname) now = `ตอนนี้ CNAME ชี้ไปที่ ${cur.cname}`
  else if (cur?.a?.length) now = `ตอนนี้ชี้ไปที่ ${cur.a.join(', ')}`
  return { state: 'waiting', label: 'DNS', detail: `รอ CNAME → ${want} (${now})${dnsSource(cur)}` }
}

// Where that answer came from. A resolver answer can be an old cached copy, so
// say so: a customer who just changed the record should not think it failed.
function dnsSource(cur: CurrentDns | null): string {
  if (cur?.via === 'authoritative') {
    return cur.nameserver ? ` · ตามที่ ${cur.nameserver} ตอบ ถ้าเพิ่งแก้ที่ผู้ให้บริการ DNS รอ 1-2 นาที` : ''
  }
  if (cur?.via === 'resolver') {
    return ' · ดูผ่าน DNS cache ค่าที่เพิ่งแก้อาจยังไม่ขึ้นจนกว่า TTL ของค่าเก่าจะหมด'
  }
  return ''
}

export function connectionCheck(d: ProgressDomain, mode: ConnectionMode | null): CheckView {
  if (d.connection.status === 'connected' && liveElsewhere(d)) {
    return { state: 'waiting', label: 'เชื่อมต่อ', detail: 'route พร้อมแล้ว · traffic จะผ่าน WAF หลังแก้ CNAME' }
  }
  switch (d.connection.status) {
    case 'connected':
      return {
        state: 'done',
        label: mode === 'direct' ? 'เชื่อมต่อ' : 'Agent',
        detail: mode === 'direct' ? 'ส่ง traffic ไปที่เซิร์ฟเวอร์ของคุณแล้ว' : 'ต่อเข้ามาแล้ว',
      }
    case 'waiting_agent':
      return { state: 'waiting', label: 'Agent', detail: 'ยังไม่ต่อ — รันคำสั่งติดตั้งบนเครื่องที่เว็บรันอยู่' }
    case 'waiting_dns':
      return { state: 'blocked', label: 'เชื่อมต่อ', detail: 'รอ DNS ก่อน' }
    case 'configuring':
      return { state: 'waiting', label: 'เชื่อมต่อ', detail: 'กำลังตั้งค่า route (ไม่เกิน 2 นาที)' }
    case 'error':
      return {
        state: 'blocked',
        label: 'เชื่อมต่อ',
        detail: 'nginx ไม่รับ config ของเซิร์ฟเวอร์นี้ — ตรวจ IP/port ของเซิร์ฟเวอร์ หรือเปลี่ยนไปใช้ Agent',
      }
    default:
      return { state: 'neutral', label: 'เชื่อมต่อ', detail: 'origin นี้สร้างก่อนระบบตรวจสถานะ — ไม่มีข้อมูลวิธีเชื่อมต่อ' }
  }
}

export function httpsCheck(d: ProgressDomain): CheckView {
  const h = d.https
  if (h.status === 'active') {
    const days = typeof h.days_remaining === 'number' ? ` · หมดอายุใน ${h.days_remaining} วัน` : ''
    return { state: 'done', label: 'HTTPS', detail: `${h.issuer || 'ออกใบรับรองแล้ว'}${days}` }
  }
  if (h.status === 'error') {
    return { state: 'blocked', label: 'HTTPS', detail: 'ตรวจใบรับรองไม่ผ่าน — ดูรายละเอียดที่หน้า Alerts' }
  }
  if (d.dns.status !== 'verified') {
    return { state: 'blocked', label: 'HTTPS', detail: 'ออกใบรับรองให้อัตโนมัติหลัง DNS ชี้มาที่เรา' }
  }
  if (liveElsewhere(d)) {
    return { state: 'blocked', label: 'HTTPS', detail: 'ออกใบรับรองให้ทันทีที่มีคนเข้าเว็บหลังแก้ CNAME' }
  }
  return { state: 'waiting', label: 'HTTPS', detail: 'ออกใบรับรองตอนมีคนเข้าเว็บครั้งแรก แล้วระบบตรวจรอบถัดไป' }
}

export interface InspectView {
  tone: 'success' | 'warning' | 'info' | 'danger'
  message: string
  mode: ConnectionMode
  address: string
  port: number
  scheme: 'http' | 'https'
}

const AGENT_DEFAULT_PORT = 3000

export function describeInspect(r: InspectResult): InspectView {
  const agent = (tone: InspectView['tone'], message: string): InspectView => ({
    tone, message, mode: 'agent', address: '', port: AGENT_DEFAULT_PORT, scheme: 'http',
  })
  if (r.already_registered) {
    return agent('danger', 'โดเมนนี้ถูกเชื่อมกับระบบแล้ว')
  }
  if (r.origin && r.recommended_mode === 'direct') {
    return {
      tone: 'success',
      message: `พบเว็บของคุณที่ ${r.origin.ip} (${r.origin.scheme.toUpperCase()}) — เชื่อมต่อได้เลย ไม่ต้องติดตั้งอะไรบนเซิร์ฟเวอร์`,
      mode: 'direct',
      address: r.origin.ip,
      port: r.origin.port,
      scheme: r.origin.scheme,
    }
  }
  switch (r.reason) {
    case 'behind_cdn':
      return agent('warning', `โดเมนนี้อยู่หลัง ${r.cdn || 'CDN อื่น'} จึงมองไม่เห็นเซิร์ฟเวอร์จริง — ใช้ Agent หรือกรอก IP จริงของเซิร์ฟเวอร์เอง`)
    case 'already_on_platform':
      return agent('info', 'โดเมนนี้ชี้มาที่ระบบเราอยู่แล้ว — ใช้ Agent หรือกรอก IP จริงของเซิร์ฟเวอร์เอง')
    case 'unreachable':
    case 'private_address':
      return agent('info', 'เข้าถึงเซิร์ฟเวอร์ปัจจุบันจากภายนอกไม่ได้ (อาจอยู่หลัง NAT/firewall) — ใช้ Agent ซึ่งไม่ต้องเปิดพอร์ต')
    default:
      return agent('info', 'ยังไม่พบเว็บที่โดเมนนี้ — ใช้ Agent บนเครื่องที่เว็บรันอยู่')
  }
}
