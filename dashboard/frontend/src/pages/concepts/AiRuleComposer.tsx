import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Sparkles, Check, X, Info, ArrowLeft, Code2 } from 'lucide-react'

const SAMPLE_SUGGESTIONS = [
  {
    id: 1,
    confidence: 94,
    title: 'บล็อก path traversal แบบ URL-encoded ซ้ำสองชั้น',
    reasoning:
      'พบ 47 ครั้งใน 6 ชม.ที่ผ่านมา จาก 3 IP ต่างกัน ทั้งหมดพยายามส่ง "%252e%252e%252f" (encode ../ ซ้ำสองรอบ) ที่ rule มาตรฐาน (930100) ตรวจจับไม่ได้เพราะ decode แค่ชั้นเดียว',
    rule: 'SecRule ARGS "@rx (?:%25){2}2e(?:%25){2}2f" \\\n  "id:9100001,phase:2,deny,status:403,msg:\'Double-encoded path traversal\'"',
    impact: 'ป้องกันได้ 47/47 request ที่เจอจริง, false positive risk: ต่ำมาก (pattern encode ซ้ำสองชั้นแทบไม่มีใน traffic ปกติ)',
  },
  {
    id: 2,
    confidence: 78,
    title: 'จำกัด rate การยิง /api/v1/reset-password',
    reasoning:
      'เห็น IP เดียวยิง endpoint นี้ 230 ครั้งใน 10 นาที (ปกติ user จริงกดไม่เกิน 2-3 ครั้ง) เข้าข่าย credential stuffing / account enumeration',
    rule: 'limit_req_zone $binary_remote_addr zone=reset_pw:10m rate=3r/m;\n# apply on location /api/v1/reset-password',
    impact: 'ลด brute-force attempt ได้ทันที, risk: ต่ำ (rate ปกติของ user จริงต่ำกว่า limit มาก)',
  },
]

export const AiRuleComposer: React.FC = () => {
  const navigate = useNavigate()
  const [decisions, setDecisions] = useState<Record<number, 'accepted' | 'rejected' | null>>({})

  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="AI Rule Composer"
        subtitle="AI วิเคราะห์ attack pattern แล้วเสนอ rule ที่ควรเพิ่มให้เลย ไม่ใช่แค่อธิบายว่ามันคืออะไร"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="AI Rule Composer" />

      {/* Explanation */}
      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> ส่วนต่อขยายของ AI Copilot ที่มีอยู่แล้ว (ตอนนี้แค่ "อธิบาย" attack log ที่เกิดขึ้น) ให้ไปอีกขั้น
          คือ "เสนอ rule ที่ควรเพิ่ม" พร้อมเหตุผลและ impact ประเมินไว้ให้ กดยอมรับได้เลยโดยไม่ต้องเขียน ModSecurity syntax เอง
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> worker พื้นหลังสแกน attack log ที่ WAF บล็อกไปแล้วเป็นระยะ หา pattern ที่เกิดซ้ำแต่ rule ปัจจุบันยังครอบไม่ถึง
          (เช่น payload variant ใหม่ที่หลบ rule เดิมได้บางส่วน) ส่งเข้า Gemini (โมเดลเดียวกับที่ AI Copilot ใช้อธิบาย log อยู่แล้ว)
          ให้ช่วยร่าง rule + อธิบายเหตุผล + ประเมิน false-positive risk คร่าวๆ จากนั้นโชว์ให้ admin ตัดสินใจ (ไม่ auto-apply เด็ดขาด)
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> ลดเวลาจาก "เห็น attack ใหม่ในกราฟ" ไปจนถึง "มี rule ป้องกันจริง" จากที่ปกติต้อง grep log เอง
          เขียน regex เอง เทสเอง เหลือแค่ "อ่านคำอธิบาย + กด accept"
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> เป็นจุดขายที่ไม่มี Cloudflare หรือ open source (ModSecurity/CrowdSec) เจ้าไหนทำ -- ทุกเจ้ามี AI
          อธิบาย log ได้ แต่ไม่มีใครให้ AI "เสนอ rule จริง" ตรงจุดนี้ ตรงกับข้อสรุปในเอกสารประเมินระบบเดิมว่าเป็นจุดที่ควรลงทุนต่อ ไม่ใช่ทิ้ง
        </p>
      </div>

      {/* Sample suggestions */}
      <div className="space-y-3">
        {SAMPLE_SUGGESTIONS.map((s) => {
          const decision = decisions[s.id]
          return (
            <div key={s.id} className="dash-card p-5 space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Sparkles size={16} className="text-purple-500 shrink-0 mt-0.5" />
                  <h3 className="font-bold text-[13.5px] font-mono m-0">{s.title}</h3>
                </div>
                <Badge color={s.confidence >= 90 ? 'success' : 'warning'}>{s.confidence}% confidence</Badge>
              </div>
              <p className="text-[11.5px] text-[var(--text-secondary)] font-mono m-0 leading-relaxed">{s.reasoning}</p>
              <div className="flex items-center gap-1.5 text-[11px] font-mono font-bold text-[var(--text-secondary)]">
                <Code2 size={12} /> Rule ที่เสนอ
              </div>
              <pre className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">
                {s.rule}
              </pre>
              <p className="text-[10.5px] text-[var(--text-muted)] font-mono m-0">{s.impact}</p>

              {decision ? (
                <div
                  className={`flex items-center gap-1.5 text-[12px] font-mono font-bold ${
                    decision === 'accepted' ? 'text-emerald-500' : 'text-[var(--text-muted)]'
                  }`}
                >
                  {decision === 'accepted' ? <Check size={14} /> : <X size={14} />}
                  {decision === 'accepted' ? 'รับแล้ว (ตัวอย่าง -- ยังไม่ได้เพิ่มจริง)' : 'ปฏิเสธแล้ว (ตัวอย่าง)'}
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Button variant="success" size="sm" onClick={() => setDecisions((p) => ({ ...p, [s.id]: 'accepted' }))}>
                    <Check size={13} /> รับ rule นี้
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setDecisions((p) => ({ ...p, [s.id]: 'rejected' }))}>
                    <X size={13} /> ปฏิเสธ
                  </Button>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default AiRuleComposer
