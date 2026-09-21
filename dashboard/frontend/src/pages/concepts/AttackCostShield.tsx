import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { DollarSign, Info, ArrowLeft, TrendingUp, AlertTriangle } from 'lucide-react'

export const AttackCostShield: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="Attack Cost Shield"
        subtitle="โชว์เป็นตัวเงินจริงว่า traffic ที่บล็อกไปช่วยประหยัดค่า cloud/bandwidth เท่าไหร่ และเตือนก่อนบิลช็อก"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="Attack Cost Shield" />

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> Pain point ที่เจ้าของเว็บยุค cloud/serverless เจอบ่อยขึ้นเรื่อยๆ: bot flood หรือ
          scraper ถล่มเว็บ ไม่ทำให้เว็บล่ม (เพราะ auto-scale รองรับได้) แต่ทำให้ "บิล cloud พุ่งกระทันหัน" -- รู้ตัวอีกที
          ตอนบิลมาปลายเดือน ฟีเจอร์นี้แปลง traffic ที่บล็อกไปเป็นตัวเงินจริง โชว์แบบ real-time ไม่ใช่แค่ตัวเลข request
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> ให้ admin ใส่ cost model คร่าวๆ ของ origin ตัวเอง (เช่น $ ต่อ 1M request, $ ต่อ GB
          egress -- ประมาณจาก pricing ของ cloud provider ที่ใช้จริง) ระบบคำนวณจาก request ที่บล็อกไปจริง (มีข้อมูลอยู่แล้ว
          ใน ClickHouse access_logs) คูณเป็นตัวเงิน พร้อม anomaly alert ถ้า traffic parern เปลี่ยนกะทันหันแบบที่จะทำให้
          บิลเดือนนี้พุ่ง (ก่อนที่จะเกิดจริง ไม่ใช่หลังบิลออก)
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> เปลี่ยนมุมมอง WAF จาก "ความปลอดภัย" (นามธรรม, ผู้บริหารมักไม่เห็นความสำคัญ) เป็น
          "ประหยัดเงินจริงเท่านี้บาท" (จับต้องได้ อธิบายให้ผู้บริหารอนุมัติงบต่อง่ายกว่ามาก) และเตือนล่วงหน้าก่อนบิลช็อก
          ไม่ใช่มาแก้ทีหลัง
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> ไม่มีคู่แข่งเจ้าไหนโชว์ "เงินที่ประหยัดได้" แบบตรงไปตรงมาขนาดนี้ (Cloudflare โชว์แค่
          จำนวน request ที่บล็อก) ระบบนี้มีข้อมูลดิบครบอยู่แล้วใน ClickHouse (access_logs ทุก request, บล็อกแล้วหรือไม่)
          แค่เพิ่มชั้นแปลงเป็นตัวเงิน ไม่ต้องสร้าง data pipeline ใหม่เลย
        </p>
      </div>

      <div className="dash-card p-5 space-y-4">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <DollarSign size={15} className="text-purple-500" /> ประมาณการเดือนนี้ (ตัวอย่าง)
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3.5 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-center">
            <div className="text-[20px] font-bold font-mono text-emerald-600 dark:text-emerald-400">$412.80</div>
            <div className="text-[10px] text-[var(--text-muted)] font-mono mt-1">ประหยัดได้เดือนนี้ (จาก request ที่บล็อก)</div>
          </div>
          <div className="p-3.5 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] text-center">
            <div className="text-[20px] font-bold font-mono">2.1M</div>
            <div className="text-[10px] text-[var(--text-muted)] font-mono mt-1">request ที่บล็อกไป (bot/scraper)</div>
          </div>
        </div>
        <div className="p-3.5 rounded-lg border border-orange-500/30 bg-orange-500/5 flex items-start gap-2.5">
          <AlertTriangle size={16} className="text-orange-500 shrink-0 mt-0.5" />
          <div>
            <div className="font-mono font-bold text-[12px] text-orange-600 dark:text-orange-400 flex items-center gap-1.5">
              <TrendingUp size={12} /> คาดการณ์: ถ้า pattern วันนี้ยังต่อเนื่อง
            </div>
            <p className="text-[11px] font-mono text-[var(--text-secondary)] m-0 mt-1">
              scraper IP ใหม่เริ่มยิงหนักขึ้น 3 เท่าตั้งแต่เมื่อคืน -- ถ้าไม่บล็อกเพิ่ม จะทำให้บิล egress เดือนนี้เกินงบประมาณ
              ~18% (ประมาณการจาก rate ปัจจุบัน)
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default AttackCostShield
