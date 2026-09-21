import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Package, Info, ArrowLeft, AlertTriangle, CheckCircle2 } from 'lucide-react'

const SAMPLE_SCRIPTS = [
  { domain: 'js.stripe.com', purpose: 'ระบบชำระเงิน', status: 'known', change: null },
  { domain: 'cdn.jsdelivr.net', purpose: 'library ที่ใช้จริง (jQuery)', status: 'known', change: null },
  { domain: 'analytics-track-cdn.ru', purpose: 'ไม่เคยเห็นมาก่อน -- เพิ่งเริ่มโหลดเมื่อ 14 ชม.ที่แล้ว', status: 'new', change: 'เพิ่มใหม่' },
  { domain: 'js.stripe.com/v3/inner-forms.js', purpose: 'ไฟล์ใหม่จาก domain เดิมที่เชื่อถือได้ แต่ path ไม่เคยเห็น', status: 'suspicious', change: 'path ใหม่ผิดปกติ' },
]

const STATUS_META: Record<string, { color: 'success' | 'danger' | 'warning'; label: string; icon: React.ReactNode }> = {
  known: { color: 'success', label: 'รู้จักแล้ว', icon: <CheckCircle2 size={12} /> },
  new: { color: 'warning', label: 'domain ใหม่', icon: <AlertTriangle size={12} /> },
  suspicious: { color: 'danger', label: 'น่าสงสัย', icon: <AlertTriangle size={12} /> },
}

export const SupplyChainMonitor: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="Third-Party Script / Supply-Chain Monitor"
        subtitle="รู้ทันทีถ้ามี script แปลกปลอมถูกฉีดเข้าหน้าเว็บ (แบบเดียวกับที่เกิดกับเว็บ checkout ดังๆ)"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="Third-Party Script / Supply-Chain Monitor" />

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> ป้องกันการโจมตีแบบ "Magecart" / web skimming -- แฮกเกอร์ฉีด JavaScript เข้าไปในเว็บ
          (ผ่าน library บุคคลที่สาม, CDN ที่ถูก compromise, หรือ CMS plugin) แอบขโมยเลขบัตรเครดิต/ข้อมูล login ตอน user
          กรอกฟอร์ม โดยที่เจ้าของเว็บไม่รู้ตัวเลยเพราะหน้าเว็บยังทำงานปกติทุกอย่าง
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> ฝัง CSP (Content-Security-Policy) report-only + collector เก็บรายชื่อ domain/script
          ทุกตัวที่หน้าเว็บจริงโหลดจริงจาก browser ของ user (ไม่ใช่แค่ดู source code) เทียบกับ "baseline" ที่เคยเห็นมาก่อน
          domain ใหม่ที่ไม่เคยเห็น หรือ path ใหม่จาก domain เดิม (เช่นโดน compromise) ขึ้นเตือนทันที ไม่ต้องรอ user มาแจ้งว่าบัตรโดนขโมย
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> เจอความผิดปกติภายในไม่กี่ชั่วโมง (ปกติ Magecart-style attack ถูกเจอหลังจากผ่านไปเป็นเดือน
          เพราะไม่มีใครมอง third-party script เป็นความเสี่ยงจนกว่าจะมีคนร้องเรียน) ลดความเสียหายทั้งด้านการเงินและชื่อเสียง
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> เป็น pain point จริงของเว็บ e-commerce ยุคนี้ทุกเว็บที่โหลด third-party script (payment,
          analytics, chat widget, A/B testing) เสี่ยงหมด แต่แทบไม่มี WAF ไหนมองไปถึง "ฝั่ง browser ของ user จริง" ส่วนใหญ่
          มองแค่ traffic ที่วิ่งผ่านตัวเองเท่านั้น (server-side) นี่คือมุมที่ขาดไปของทุกเจ้า ไม่ใช่แค่เรา
        </p>
      </div>

      <div className="dash-card p-5 space-y-3">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <Package size={15} className="text-purple-500" /> Script ที่หน้าเว็บโหลดจริง (ตัวอย่าง)
        </h3>
        <div className="space-y-2">
          {SAMPLE_SCRIPTS.map((s) => {
            const meta = STATUS_META[s.status]
            return (
              <div
                key={s.domain}
                className="p-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] flex items-center justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="font-mono font-semibold text-[12px] truncate">{s.domain}</div>
                  <div className="font-mono text-[10.5px] text-[var(--text-muted)]">{s.purpose}</div>
                </div>
                <Badge color={meta.color}>
                  {meta.icon} {meta.label}
                </Badge>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export default SupplyChainMonitor
