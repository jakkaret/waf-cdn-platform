import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Bot, Info, ArrowLeft, User, Sparkles } from 'lucide-react'

const SAMPLE_SESSIONS = [
  { id: 'sess_a91f', actor: 'human', confidence: 96, agent: null, action: 'เลื่อนดูสินค้า, คลิกปกติ, พิมพ์ช้า' },
  { id: 'sess_c22d', actor: 'agent', confidence: 91, agent: 'OpenAI Atlas', action: 'เติมฟอร์ม checkout ใน 0.3 วินาที, ไม่มี mouse movement' },
  { id: 'sess_f7b1', actor: 'agent', confidence: 88, agent: 'Perplexity Comet', action: 'ดึงราคาสินค้าทุกตัวเรียงลำดับ, ไม่โหลดรูปภาพ' },
  { id: 'sess_9e30', actor: 'uncertain', confidence: 54, agent: null, action: 'pattern ผสม -- คลิกบางจุดเป็นมนุษย์ บางจุดเร็วผิดปกติ' },
]

const ACTOR_META: Record<string, { color: 'success' | 'brand' | 'warning'; icon: React.ReactNode; label: string }> = {
  human: { color: 'success', icon: <User size={11} />, label: 'มนุษย์' },
  agent: { color: 'brand', icon: <Bot size={11} />, label: 'AI Agent' },
  uncertain: { color: 'warning', icon: <Sparkles size={11} />, label: 'ไม่แน่ใจ' },
}

export const AgenticTrafficGovernance: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="Agentic Traffic Governance"
        subtitle="แยกให้ออกว่า session นี้เป็น 'มนุษย์คลิกเอง' หรือ 'AI agent กระทำการแทน' แล้วตั้ง policy คนละแบบ"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="Agentic Traffic Governance" />
      <Badge color="purple">ENTERPRISE TIER</Badge>

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> ปัญหาใหม่ล่าสุดของปี 2026 ที่ต่างจาก "bot scraping" เดิม -- AI browser agent จริงๆ
          (OpenAI Atlas, Perplexity Comet ฯลฯ) เปิด browser จริง มี cookie, session, user-agent เหมือนมนุษย์ทุกอย่าง
          แต่ "กระทำการแทน" user จริง (กรอกฟอร์ม, ซื้อของ, สมัครสมาชิก) WAF แบบเดิมจับไม่ได้เลยเพราะไม่มี signature
          ที่ต่างจาก human -- ต้องแยกที่ "พฤติกรรม" ไม่ใช่ "รูปร่าง traffic"
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> ฝัง client-side JS เก็บสัญญาณที่ agent เลียนแบบยากจริง (จังหวะเมาส์/คีย์บอร์ด,
          canvas rendering entropy, เวลาตอบสนองระหว่าง event) คำนวณ confidence score ต่อ session ว่าเป็นมนุษย์/agent/ไม่แน่ใจ
          แล้วให้ admin ตั้ง policy แยกกัน เช่น agent กรอก checkout ได้แต่ต้องผ่าน step ยืนยันเพิ่ม, agent ดึงราคาสินค้า
          จำนวนมากเกิน threshold ให้ throttle แทนบล็อกทันที (กัน false positive กับ agent ที่ user ตั้งใจสั่งงานจริง)
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> ป้องกัน checkout fraud ที่ agent ทำแทนโดยไม่ได้รับอนุญาตจริง และเปิดทางให้เว็บ "อนุญาต"
          agent ที่ user สั่งงานเองแบบมีเงื่อนไข แทนที่จะบล็อกรวมหรือปล่อยรวม
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> ข้อมูลจริงต้นปี 2026 ชี้ว่า agentic browser (นำโดย Perplexity Comet และ OpenAI Atlas)
          คิดเป็น ~71% ของ traffic ที่เป็น agent ทั้งหมดแล้ว และผู้เชี่ยวชาญมองว่า "agentic identity detection" กำลังกลาย
          เป็นมาตรฐานพื้นฐานที่ enterprise ทุกเจ้าต้องมี ไม่ใช่ทางเลือกอีกต่อไป (อ้างอิง: HUMAN Security "State of
          Agentic Traffic" เม.ย. 2026, Akamai "AI Pulse" 2026) -- Cloudflare เองก็เพิ่งเปิดตัว "Precursor" client-side
          bot/session detection ปี 2026 เพื่อรับมือเรื่องนี้โดยเฉพาะ
        </p>
      </div>

      <div className="dash-card p-5 space-y-3">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <Bot size={15} className="text-purple-500" /> Session ล่าสุดที่วิเคราะห์ (ตัวอย่าง)
        </h3>
        <div className="space-y-2">
          {SAMPLE_SESSIONS.map((s) => {
            const meta = ACTOR_META[s.actor]
            return (
              <div key={s.id} className="p-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] text-[var(--text-muted)]">{s.id}</span>
                  <div className="flex items-center gap-2">
                    {s.agent && <span className="text-[10.5px] font-mono text-[var(--text-muted)]">{s.agent}</span>}
                    <Badge color={meta.color}>
                      {meta.icon} {meta.label} {s.confidence}%
                    </Badge>
                  </div>
                </div>
                <div className="text-[11px] font-mono text-[var(--text-secondary)]">{s.action}</div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export default AgenticTrafficGovernance
