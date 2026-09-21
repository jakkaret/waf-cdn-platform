import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Fish, Info, ArrowLeft, AlertTriangle } from 'lucide-react'

const SAMPLE_TRAPS = [
  { name: 'Honeytoken API key ใน JS bundle', type: 'API key ปลอม', triggers: 0, status: 'เงียบ (ปกติ)' },
  { name: 'Booby-trapped field: "coupon_internal"', type: 'ฟอร์มที่มองไม่เห็น', triggers: 3, status: 'มี bot กรอกฟอร์มอัตโนมัติ 3 ครั้ง' },
  { name: 'Fake admin endpoint /wp-admin-legacy', type: 'เส้นทางล่อ', triggers: 12, status: 'มีคนพยายาม brute-force เข้าเส้นทางนี้' },
]

export const DeceptionLayer: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="Deception Layer (Honeytokens & Canary Traps)"
        subtitle="วางกับดักปลอมทิ้งไว้ ใครแตะเข้าคือผิดปกติ 100% ไม่มี false positive เลย"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="Deception Layer (Honeytokens & Canary Traps)" />
      <Badge color="purple">ENTERPRISE TIER</Badge>

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> ฟีเจอร์ป้องกันฝั่งตรงข้ามกับ rule/pattern-matching ที่ WAF ใช้อยู่แล้วทั้งหมด --
          แทนที่จะพยายามแยก "traffic ดีกับไม่ดี" (ซึ่งมี false positive เสมอ) วางของปลอมที่ไม่มีใครมีเหตุผลไปแตะเลย
          ถ้ามีใครแตะ = ผิดปกติแน่นอน 100% ไม่ต้องเดา
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> 3 แบบหลัก -- (1) Honeytoken API key: ฝัง API key ปลอมไว้ใน JS/HTML source
          ที่ scraper มักจะไปสแกนหา ใครเอาไปใช้จริง = ยืนยันว่ากำลัง recon อยู่ (2) Booby-trapped form field: ฟิลด์ที่
          ซ่อนไม่ให้ user จริงเห็น (CSS display:none) แต่ bot ที่กรอกฟอร์มอัตโนมัติแบบไม่อ่าน DOM จะกรอกเข้ามา (3) Decoy
          path: เส้นทางที่ดูเหมือนของจริง (เช่น /wp-admin-legacy) ไม่มีใน sitemap ไม่มีลิงก์ไปหา มีแต่คนที่ brute-force
          scan เท่านั้นที่จะเจอ ทุกอันเชื่อม alert เข้า Telegram เดียวกับระบบ alert ที่มีอยู่แล้ว
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> จับ "การสอดแนมก่อนโจมตีจริง" (reconnaissance) ได้ตั้งแต่ก่อนการโจมตีจริงเกิดขึ้น
          และยังจับได้แม้ attacker หลบ ModSecurity signature ได้แล้ว (เพราะไม่ได้พึ่ง signature เลย) เสริมอีกชั้นที่ระบบ
          rule-based ปัจจุบันไม่มี
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> deception technology เป็นเทรนด์จริงที่กำลังโตในปี 2026 โดยเฉพาะ honeytoken เพราะ
          deploy ง่าย (ใช้เวลาแค่ครึ่งวันตามคู่มืออุตสาหกรรม) ให้ผล high-fidelity สูงมาก (ทุก trigger คือของจริง ไม่มี
          noise) และยังทำงานต่อแม้ credential รั่วไปแล้ว (honeytoken ที่ถูกขโมยไปใช้ยัง beacon กลับมาบอกตำแหน่ง attacker ได้)
          เป็นฟีเจอร์ระดับ enterprise ที่ยังไม่มีคู่แข่งระดับเรานำเสนอเลย
        </p>
      </div>

      <div className="dash-card p-5 space-y-3">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <Fish size={15} className="text-purple-500" /> กับดักที่วางไว้ (ตัวอย่าง)
        </h3>
        <div className="space-y-2">
          {SAMPLE_TRAPS.map((t) => (
            <div key={t.name} className="p-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="font-mono font-semibold text-[12px]">{t.name}</div>
                <div className="font-mono text-[10.5px] text-[var(--text-muted)]">{t.type}</div>
              </div>
              <Badge color={t.triggers > 0 ? 'danger' : 'gray'}>
                {t.triggers > 0 && <AlertTriangle size={10} />} {t.triggers} trigger
              </Badge>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default DeceptionLayer
