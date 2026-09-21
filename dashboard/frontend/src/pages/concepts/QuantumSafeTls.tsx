import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Lock, Info, ArrowLeft, CheckCircle2 } from 'lucide-react'

const SAMPLE_DOMAINS = [
  { domain: 'shop.example.com', handshake: 'Hybrid X25519+ML-KEM-768', status: 'quantum-safe' },
  { domain: 'api.example.com', handshake: 'X25519 (classical only)', status: 'legacy' },
  { domain: 'legacy-app.example.com', handshake: 'TLS 1.2 RSA', status: 'at_risk' },
]

const STATUS_META: Record<string, { color: 'success' | 'warning' | 'danger'; label: string }> = {
  'quantum-safe': { color: 'success', label: 'Quantum-Safe' },
  legacy: { color: 'warning', label: 'Classical เท่านั้น' },
  at_risk: { color: 'danger', label: 'เสี่ยง (TLS เก่า)' },
}

export const QuantumSafeTls: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="Post-Quantum TLS Readiness"
        subtitle="ดูภาพรวมว่าโดเมนไหนพร้อมรับมือคอมพิวเตอร์ควอนตัมแล้วบ้าง ก่อนที่ข้อมูลเข้ารหัสวันนี้จะถูกถอดย้อนหลังได้ในอนาคต"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="Post-Quantum TLS Readiness" />
      <Badge color="purple">ENTERPRISE TIER</Badge>

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> การเข้ารหัส TLS แบบเดิม (RSA/ECDHE) จะถูกคอมพิวเตอร์ควอนตัมถอดได้ในอนาคต -- ปัญหาคือ
          ข้อมูลที่ถูก "ดักเก็บไว้วันนี้" (attacker บันทึก traffic เข้ารหัสไว้เฉยๆ) จะถูกถอดย้อนหลังได้ทันทีที่ควอนตัมพร้อม
          (เรียกว่า "harvest now, decrypt later") ฟีเจอร์นี้แสดงภาพรวมว่าแต่ละโดเมนของคุณใช้ TLS แบบไหนอยู่ และช่วย migrate
          ไปใช้ hybrid post-quantum key exchange
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> Caddy/TLS termination รองรับ hybrid key exchange (คลาสสิก + post-quantum พร้อมกัน
          เช่น X25519+ML-KEM -- เข้ากันได้กับ browser เก่าด้วย ไม่ต้องเลือกอย่างใดอย่างหนึ่ง) หน้านี้สแกนทุกโดเมนที่ผูกกับ
          ระบบ แสดงว่าตัวไหน handshake แบบไหนอยู่ พร้อมปุ่ม "เปิด hybrid PQC" ทีละโดเมนโดยไม่กระทบ user เก่า
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> ปิด gap ด้าน compliance ระยะยาวที่ธุรกิจ regulated (การเงิน, สุขภาพ, ราชการ) เริ่มถูกถาม
          หาแล้วจริงตอนนี้ และเตรียมพร้อมก่อนที่มาตรฐานจะบังคับ ไม่ต้องรีบทำทีเดียวตอนใกล้เส้นตาย
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> ข้อมูลจริงต้นปี 2026: Fortune 500 ที่ทำ cryptographic inventory เสร็จแล้วโตจาก 12%
          (ปลายปี 2024) เป็น ~38% แล้ว AWS deploy ML-KEM ครอบคลุม CloudFront/ALB/NLB/KMS ไปแล้ว ปลายปี 2025 Google Cloud
          ก็เปิด ML-KEM ใน Cloud KMS แบบ production แล้ว F5 ประกาศรวม "AI-driven protection + zero trust + post-quantum
          readiness" เป็นแพ็กเกจเดียวในปี 2026 -- เป็นทิศทางที่ผู้เล่นใหญ่ระดับ enterprise กำลังเดินไปพร้อมกันจริง
        </p>
      </div>

      <div className="dash-card p-5 space-y-3">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <Lock size={15} className="text-purple-500" /> สถานะ TLS ต่อโดเมน (ตัวอย่าง)
        </h3>
        <div className="space-y-2">
          {SAMPLE_DOMAINS.map((d) => {
            const meta = STATUS_META[d.status]
            return (
              <div key={d.domain} className="p-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-mono font-semibold text-[12px]">{d.domain}</div>
                  <div className="font-mono text-[10.5px] text-[var(--text-muted)]">{d.handshake}</div>
                </div>
                <Badge color={meta.color}>
                  {d.status === 'quantum-safe' && <CheckCircle2 size={10} />} {meta.label}
                </Badge>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export default QuantumSafeTls
