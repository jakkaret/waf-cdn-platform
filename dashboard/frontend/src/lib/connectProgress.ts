// Pure helpers behind ConnectSiteFlow and DomainStatusCard: what to show for
// an /api/onboarding/inspect result and for each /progress check. Kept out of
// the components so every branch is unit-tested.
//
// Every text helper takes the UI language last; Thai is the default because
// the copy was written (and is tested) in Thai first.
import type { InspectResult, ProgressDomain, ConnectionMode, CurrentDns } from '../api/onboarding'
import type { OriginAdjusted } from '../types'

type Lang = 'en' | 'th'
const L = (lang: Lang, th: string, en: string) => (lang === 'th' ? th : en)

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

export function dnsCheck(d: ProgressDomain, lang: Lang = 'th'): CheckView {
  const cur = d.dns.current
  const want = d.dns.instructions.cname_record.value
  if (d.dns.status === 'verified') {
    if (cur && liveElsewhere(d)) {
      return {
        state: 'waiting',
        label: 'DNS',
        detail: L(
          lang,
          `ยืนยันโดเมนแล้ว · ขั้นที่ 2 แก้ CNAME ให้ชี้มาที่ ${want} (ตอนนี้ยังชี้ไปที่ ${pointsAt(cur)})`,
          `Domain verified · step 2: change the CNAME to point to ${want} (it still points to ${pointsAt(cur)})`,
        ),
      }
    }
    return { state: 'done', label: 'DNS', detail: L(lang, `ชี้มาที่ ${want} แล้ว`, `Points to ${want}`) }
  }
  if (cur?.cname_ok || cur?.txt_ok) {
    const which = cur.cname_ok ? 'CNAME' : 'TXT'
    return {
      state: 'waiting',
      label: 'DNS',
      detail: L(lang, `${which} ถูกต้องแล้ว กำลังยืนยัน (ไม่เกิน 1 นาที)`, `${which} is correct, verifying (up to 1 minute)`),
    }
  }
  if (cur && liveElsewhere(d)) {
    return {
      state: 'waiting',
      label: 'DNS',
      detail:
        L(
          lang,
          `เว็บนี้ใช้งานอยู่ (ตอนนี้ชี้ไปที่ ${pointsAt(cur)}) · ขั้นที่ 1 เพิ่ม TXT ด้านล่างก่อน ยืนยันแล้วค่อยแก้ CNAME เว็บจะไม่สะดุด`,
          `This site is live (it points to ${pointsAt(cur)}) · step 1: add the TXT record below first, then change the CNAME once verified, so the site does not go down`,
        ) + dnsSource(cur, lang),
    }
  }
  let now = L(lang, 'ยังไม่พบ record', 'no record found yet')
  if (cur?.cname) now = L(lang, `ตอนนี้ CNAME ชี้ไปที่ ${cur.cname}`, `the CNAME now points to ${cur.cname}`)
  else if (cur?.a?.length) now = L(lang, `ตอนนี้ชี้ไปที่ ${cur.a.join(', ')}`, `it now points to ${cur.a.join(', ')}`)
  return {
    state: 'waiting',
    label: 'DNS',
    detail: L(lang, `รอ CNAME → ${want} (${now})`, `Waiting for CNAME → ${want} (${now})`) + dnsSource(cur, lang),
  }
}

// Where that answer came from. A resolver answer can be an old cached copy, so
// say so: a customer who just changed the record should not think it failed.
function dnsSource(cur: CurrentDns | null, lang: Lang): string {
  if (cur?.via === 'authoritative') {
    return cur.nameserver
      ? L(
          lang,
          ` · ตามที่ ${cur.nameserver} ตอบ ถ้าเพิ่งแก้ที่ผู้ให้บริการ DNS รอ 1-2 นาที`,
          ` · as answered by ${cur.nameserver}; if you just changed it at your DNS provider, wait 1-2 minutes`,
        )
      : ''
  }
  if (cur?.via === 'resolver') {
    return L(
      lang,
      ' · ดูผ่าน DNS cache ค่าที่เพิ่งแก้อาจยังไม่ขึ้นจนกว่า TTL ของค่าเก่าจะหมด',
      ' · read through a DNS cache; a value you just changed may not show until the old value’s TTL runs out',
    )
  }
  return ''
}

export function connectionCheck(d: ProgressDomain, mode: ConnectionMode | null, lang: Lang = 'th'): CheckView {
  const connect = L(lang, 'เชื่อมต่อ', 'Connection')
  if (d.connection.status === 'connected' && liveElsewhere(d)) {
    return {
      state: 'waiting',
      label: connect,
      detail: L(lang, 'route พร้อมแล้ว · traffic จะผ่าน WAF หลังแก้ CNAME', 'Route ready · traffic goes through the WAF once the CNAME is changed'),
    }
  }
  switch (d.connection.status) {
    case 'connected':
      return {
        state: 'done',
        label: mode === 'direct' ? connect : 'Agent',
        detail:
          mode === 'direct'
            ? L(lang, 'ส่ง traffic ไปที่เซิร์ฟเวอร์ของคุณแล้ว', 'Traffic is sent to your server')
            : L(lang, 'ต่อเข้ามาแล้ว', 'Connected'),
      }
    case 'waiting_agent':
      return {
        state: 'waiting',
        label: 'Agent',
        detail: L(lang, 'ยังไม่ต่อ — รันคำสั่งติดตั้งบนเครื่องที่เว็บรันอยู่', 'Not connected yet — run the install command on the machine the site runs on'),
      }
    case 'waiting_dns':
      return { state: 'blocked', label: connect, detail: L(lang, 'รอ DNS ก่อน', 'Waiting for DNS first') }
    case 'configuring':
      return { state: 'waiting', label: connect, detail: L(lang, 'กำลังตั้งค่า route (ไม่เกิน 2 นาที)', 'Setting up the route (up to 2 minutes)') }
    case 'error':
      return {
        state: 'blocked',
        label: connect,
        detail: L(
          lang,
          'nginx ไม่รับ config ของเซิร์ฟเวอร์นี้ — ตรวจ IP/port ของเซิร์ฟเวอร์ หรือเปลี่ยนไปใช้ Agent',
          'nginx rejected the config for this server — check the server IP/port, or switch to the Agent',
        ),
      }
    default:
      return {
        state: 'neutral',
        label: connect,
        detail: L(
          lang,
          'origin นี้สร้างก่อนระบบตรวจสถานะ — ไม่มีข้อมูลวิธีเชื่อมต่อ',
          'This origin was created before status checks existed — there is no connection data',
        ),
      }
  }
}

export function httpsCheck(d: ProgressDomain, lang: Lang = 'th'): CheckView {
  const h = d.https
  if (h.status === 'active') {
    const days =
      typeof h.days_remaining === 'number' ? L(lang, ` · หมดอายุใน ${h.days_remaining} วัน`, ` · expires in ${h.days_remaining} days`) : ''
    return { state: 'done', label: 'HTTPS', detail: `${h.issuer || L(lang, 'ออกใบรับรองแล้ว', 'Certificate issued')}${days}` }
  }
  if (h.status === 'error') {
    return {
      state: 'blocked',
      label: 'HTTPS',
      detail: L(lang, 'ตรวจใบรับรองไม่ผ่าน — ดูรายละเอียดที่หน้า Alerts', 'Certificate check failed — see the details on the Alerts page'),
    }
  }
  if (d.dns.status !== 'verified') {
    return {
      state: 'blocked',
      label: 'HTTPS',
      detail: L(lang, 'ออกใบรับรองให้อัตโนมัติหลัง DNS ชี้มาที่เรา', 'A certificate is issued automatically once DNS points to us'),
    }
  }
  if (liveElsewhere(d)) {
    return {
      state: 'blocked',
      label: 'HTTPS',
      detail: L(lang, 'ออกใบรับรองให้ทันทีที่มีคนเข้าเว็บหลังแก้ CNAME', 'A certificate is issued on the first visit after the CNAME is changed'),
    }
  }
  return {
    state: 'waiting',
    label: 'HTTPS',
    detail: L(
      lang,
      'ออกใบรับรองตอนมีคนเข้าเว็บครั้งแรก แล้วระบบตรวจรอบถัดไป',
      'A certificate is issued on the first visit, then checked on the next round',
    ),
  }
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

export function describeInspect(r: InspectResult, lang: Lang = 'th'): InspectView {
  const agent = (tone: InspectView['tone'], message: string): InspectView => ({
    tone, message, mode: 'agent', address: '', port: AGENT_DEFAULT_PORT, scheme: 'http',
  })
  if (r.already_registered) {
    return agent('danger', L(lang, 'โดเมนนี้ถูกเชื่อมกับระบบแล้ว', 'This domain is already connected to the platform'))
  }
  if (r.origin && r.recommended_mode === 'direct') {
    return {
      tone: 'success',
      message: L(
        lang,
        `พบเว็บของคุณที่ ${r.origin.ip} (${r.origin.scheme.toUpperCase()}) — เชื่อมต่อได้เลย ไม่ต้องติดตั้งอะไรบนเซิร์ฟเวอร์`,
        `Found your site at ${r.origin.ip} (${r.origin.scheme.toUpperCase()}) — you can connect now, nothing to install on the server`,
      ),
      mode: 'direct',
      address: r.origin.ip,
      port: r.origin.port,
      scheme: r.origin.scheme,
    }
  }
  switch (r.reason) {
    case 'behind_cdn':
      return agent(
        'warning',
        L(
          lang,
          `โดเมนนี้อยู่หลัง ${r.cdn || 'CDN อื่น'} จึงมองไม่เห็นเซิร์ฟเวอร์จริง — ใช้ Agent หรือกรอก IP จริงของเซิร์ฟเวอร์เอง`,
          `This domain is behind ${r.cdn || 'another CDN'}, so the real server is hidden — use the Agent or enter the server’s real IP`,
        ),
      )
    case 'already_on_platform':
      return agent(
        'info',
        L(
          lang,
          'โดเมนนี้ชี้มาที่ระบบเราอยู่แล้ว — ใช้ Agent หรือกรอก IP จริงของเซิร์ฟเวอร์เอง',
          'This domain already points to our platform — use the Agent or enter the server’s real IP',
        ),
      )
    case 'unreachable':
    case 'private_address':
      return agent(
        'info',
        L(
          lang,
          'เข้าถึงเซิร์ฟเวอร์ปัจจุบันจากภายนอกไม่ได้ (อาจอยู่หลัง NAT/firewall) — ใช้ Agent ซึ่งไม่ต้องเปิดพอร์ต',
          'The current server cannot be reached from outside (it may be behind NAT/firewall) — use the Agent, which needs no open port',
        ),
      )
    default:
      return agent(
        'info',
        L(lang, 'ยังไม่พบเว็บที่โดเมนนี้ — ใช้ Agent บนเครื่องที่เว็บรันอยู่', 'No site found at this domain yet — use the Agent on the machine the site runs on'),
      )
  }
}

// Toast text when the backend moved a direct route to https:443 because the
// server forces HTTPS (http:80 would redirect forever behind the WAF).
export function describeOriginAdjusted(a: OriginAdjusted | null | undefined, lang: Lang = 'th'): string | null {
  if (!a || a.reason !== 'origin_forces_https') return null
  const code = a.status ? L(lang, ` (ตอบ ${a.status})`, ` (answered ${a.status})`) : ''
  return L(
    lang,
    `เซิร์ฟเวอร์บังคับใช้ HTTPS${code} — เปลี่ยนเป็น ${a.scheme}:${a.port} ให้แล้ว ไม่งั้นเว็บจะ redirect วนไม่จบ`,
    `The server forces HTTPS${code} — switched to ${a.scheme}:${a.port}, otherwise the site would redirect in a loop`,
  )
}
