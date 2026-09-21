import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Bug, Info, ArrowLeft, Clock, ShieldCheck } from 'lucide-react'

const SAMPLE_CVES = [
  {
    cve: 'CVE-2026-31402',
    product: 'WordPress plugin: WP Fastest Cache 1.2.8',
    severity: 'CRITICAL',
    published: '6 ชม.ที่แล้ว',
    matched: true,
    status: 'patched',
    detail: 'ตรวจพบว่า origin ของคุณรัน plugin เวอร์ชันนี้จริง (จาก response header + /wp-content/plugins/ path) -- ออก virtual patch อัตโนมัติแล้ว',
  },
  {
    cve: 'CVE-2026-30119',
    product: 'WooCommerce 8.4.x (unauthenticated SQLi)',
    severity: 'CRITICAL',
    published: '1 วันที่แล้ว',
    matched: false,
    status: 'not_applicable',
    detail: 'ไม่พบ WooCommerce บน origin ของคุณ -- ข้าม',
  },
  {
    cve: 'CVE-2026-29887',
    product: 'nginx 1.24 (HTTP/2 request smuggling)',
    severity: 'HIGH',
    published: '3 วันที่แล้ว',
    matched: true,
    status: 'pending_review',
    detail: 'origin รัน nginx เวอร์ชันที่เข้าข่าย -- rule ร่างไว้แล้ว รอ admin ตรวจก่อน apply (มีความเสี่ยง false positive กว่า WP)',
  },
]

const STATUS_META: Record<string, { color: 'success' | 'warning' | 'gray'; label: string }> = {
  patched: { color: 'success', label: 'PATCHED' },
  pending_review: { color: 'warning', label: 'รอตรวจ' },
  not_applicable: { color: 'gray', label: 'ไม่เกี่ยวข้อง' },
}

export const CveAutoPatch: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="Auto Virtual-Patch จาก CVE Feed"
        subtitle="CVE ใหม่ออกกี่ชม. rule ป้องกันก็ออกให้เท่านั้น ไม่ต้องรอ patch จริงจากเจ้าของ plugin/framework"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="Auto Virtual-Patch จาก CVE Feed" />

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> ต่อยอด "Virtual Patching model" ที่เป็นจุดขายอยู่แล้วของระบบนี้ (ตรงกับ pain point
          เว็บเก่า/SME ที่ patch เองไม่ทันจริง) ให้เชื่อมกับ CVE feed สาธารณะ (NVD/GitHub Advisory) อัตโนมัติ
          แทนที่ admin ต้องคอยตามข่าว CVE เองแล้วมาเขียน rule เอง
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> worker พื้นหลัง poll CVE feed ทุกชม. กรองเฉพาะ CVE ที่เกี่ยวกับ CMS/framework/plugin
          ที่ origin คุณใช้จริง (fingerprint จาก response header, path pattern, banner ฯลฯ -- คล้ายที่ CDN dashboard
          ตรวจ SSL/TLS อยู่แล้ว) ให้ AI (Gemini เดียวกับ Copilot) ร่าง ModSecurity rule ปิดช่องโหว่นั้นเฉพาะจุด
          CVE severity CRITICAL ของ product ที่ยืนยันชัด (เช่น WordPress plugin เวอร์ชันตรงเป๊ะ) apply อัตโนมัติทันที
          ส่วนที่เสี่ยง false positive กว่า (เช่น เดาจาก banner คร่าวๆ) รอ admin กดยืนยันก่อน
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> ปิด gap ระหว่าง "CVE ประกาศ" กับ "เว็บจริงได้รับการป้องกัน" จากที่ปกติเป็นวัน/สัปดาห์
          (รอ plugin author ออก patch, รอ admin update) เหลือเป็นชั่วโมง โดยไม่ต้องแตะโค้ด origin เลย
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> ตรงกับ pain point ที่เอกสารประเมินระบบเดิมชี้ไว้ว่า "Virtual Patching ตรงกับ SME/เว็บเก่าจริง
          เป็น niche ที่ Cloudflare ทำได้แต่ไม่ได้ทำการตลาดขนาดนี้" -- ตอนนี้ระบบมี virtual patching อยู่แล้วแต่เป็น manual
          ทำ auto จาก CVE feed คือทำให้จุดขายเดิมแข็งแรงขึ้นไปอีกขั้น ไม่ใช่ฟีเจอร์ใหม่ทั้งหมด
        </p>
      </div>

      <div className="dash-card p-5 space-y-3">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <Bug size={15} className="text-purple-500" /> CVE ล่าสุดที่ระบบเจอ (ตัวอย่าง)
        </h3>
        <div className="space-y-2">
          {SAMPLE_CVES.map((c) => {
            const meta = STATUS_META[c.status]
            return (
              <div key={c.cve} className="p-3.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-[12px]">{c.cve}</span>
                    <Badge color={c.severity === 'CRITICAL' ? 'danger' : 'warning'}>{c.severity}</Badge>
                  </div>
                  <Badge color={meta.color}>{meta.label}</Badge>
                </div>
                <div className="font-mono text-[11.5px] text-[var(--text-secondary)]">{c.product}</div>
                <div className="flex items-center gap-1.5 text-[10.5px] text-[var(--text-muted)] font-mono">
                  <Clock size={11} /> ประกาศ {c.published}
                </div>
                <div className="text-[10.5px] text-[var(--text-muted)] font-mono flex items-start gap-1.5">
                  {c.status === 'patched' && <ShieldCheck size={11} className="text-emerald-500 shrink-0 mt-0.5" />}
                  <span>{c.detail}</span>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export default CveAutoPatch
