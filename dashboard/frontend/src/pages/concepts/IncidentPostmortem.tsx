import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { FileText, Info, ArrowLeft, AlertTriangle, Download, Sparkles } from 'lucide-react'

export const IncidentPostmortem: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="AI Incident Postmortem"
        subtitle="พอมี incident จริงเกิดขึ้น ให้ AI ร่างรายงานสรุปให้อัตโนมัติ ไม่ต้องเขียนเอง"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="AI Incident Postmortem" />

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> เมื่อเกิดเหตุการณ์ผิดปกติ (attack spike ผิดปกติ, origin ดับ, cert หมดอายุกะทันหัน ฯลฯ)
          ระบบสร้างร่างรายงาน postmortem ให้อัตโนมัติ -- สรุปว่าเกิดอะไร เมื่อไหร่ ผลกระทบแค่ไหน สาเหตุที่น่าจะเป็น และควรทำอะไรต่อ
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> ใช้ signal ที่มีอยู่แล้วทั้งหมดในระบบ (alerts_table, ClickHouse access_logs,
          waf_ssl_certs, waf_status_history ที่เพิ่งสร้างคืนนี้) มารวมเป็น timeline เดียว ส่งให้ Gemini (โมเดลเดียวกับ AI Copilot)
          สรุปเป็นภาษาคนอ่านง่าย พร้อม timeline กราฟ แล้วให้ admin แก้ไข/เพิ่มเติมก่อน export เป็น PDF หรือแชร์ในทีม
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> ปกติเขียน postmortem เองต้องไล่ log หลายที่ (Telegram alert, dashboard, ClickHouse) เอามาต่อกันเอง
          ใช้เวลาเป็นชม. ระบบนี้ทำ first draft ให้ใน 1 นาที เหลือแค่ตรวจทาน
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> ไม่มีคู่แข่งเจ้าไหน (Cloudflare, CrowdSec, Wazuh) ทำเรื่องนี้เลย เพราะต้องมี AI ที่เข้าใจ context
          ของระบบตัวเองอยู่แล้ว (เหมือน AI Copilot ที่เรามี) เจ้าอื่นไม่มี ต่อยอดจุดแข็งเดิมที่สุดในลิสต์นี้
        </p>
      </div>

      <div className="dash-card p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-[13.5px] font-bold font-mono m-0 flex items-center gap-2">
            <AlertTriangle size={16} className="text-red-500" /> Incident #INC-2026-0847 (ตัวอย่าง)
          </h3>
          <Badge color="danger">RESOLVED</Badge>
        </div>

        <div className="grid grid-cols-3 gap-3 text-center">
          <div className="p-2.5 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
            <div className="text-[16px] font-bold font-mono">23 นาที</div>
            <div className="text-[10px] text-[var(--text-muted)] font-mono">ระยะเวลากระทบ</div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
            <div className="text-[16px] font-bold font-mono">1,204</div>
            <div className="text-[10px] text-[var(--text-muted)] font-mono">request บล็อกผิด</div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
            <div className="text-[16px] font-bold font-mono">2</div>
            <div className="text-[10px] text-[var(--text-muted)] font-mono">origin กระทบ</div>
          </div>
        </div>

        <div className="space-y-1.5 text-[11.5px] font-mono">
          <div className="flex items-start gap-2">
            <Sparkles size={13} className="text-purple-500 shrink-0 mt-0.5" />
            <p className="m-0 text-[var(--text-secondary)] leading-relaxed">
              <strong>AI สรุป:</strong> เวลา 03:14–03:37 rule paranoia_level ที่เพิ่งปรับจาก 1 เป็น 3 เมื่อ 03:10
              เริ่มบล็อก request ปกติที่มี query string ยาว (เช่น filter สินค้าหลายตัว) ของ 2 origin ที่ใช้ pattern URL คล้ายกัน
              false positive rate พุ่งจาก 0.2% เป็น 18% ก่อนถูก rollback อัตโนมัติ
            </p>
          </div>
          <div className="flex items-start gap-2">
            <Sparkles size={13} className="text-purple-500 shrink-0 mt-0.5" />
            <p className="m-0 text-[var(--text-secondary)] leading-relaxed">
              <strong>ข้อเสนอแนะ:</strong> ก่อนปรับ paranoia_level ควรรัน detection_only mode 24 ชม.ก่อน enforce จริง
              (ตรงกับ Operational Guideline ที่มีอยู่แล้วในหน้า Settings -- แค่ยังไม่มีใครบังคับใช้จริง)
            </p>
          </div>
        </div>

        <Button variant="secondary" disabled>
          <Download size={13} /> Export PDF (ตัวอย่าง -- ยังกดไม่ได้จริง)
        </Button>
      </div>
    </div>
  )
}

export default IncidentPostmortem
