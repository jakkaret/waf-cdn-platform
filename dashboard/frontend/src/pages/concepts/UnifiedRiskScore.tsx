import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Gauge, Info, ArrowLeft } from 'lucide-react'

const SIGNAL_ROWS = [
  { source: 'WAF Rule Match', weight: '35%', value: 'SQLi pattern (rule 942100)', score: 90 },
  { source: 'Bot/Session Score', weight: '25%', value: 'Headless browser signature', score: 70 },
  { source: 'Rate Limit', weight: '15%', value: '340 req/min จาก IP เดียว (limit: 60)', score: 85 },
  { source: 'Threat Intel (community)', weight: '15%', value: 'rule นี้ trending ข้าม 4 tenant คืนนี้', score: 60 },
  { source: 'API Schema Anomaly', weight: '10%', value: 'field ที่ไม่เคยส่งมาก่อนใน payload', score: 40 },
]

export const UnifiedRiskScore: React.FC = () => {
  const navigate = useNavigate()
  const totalScore = 78
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="Unified Risk Score (WAAP Consolidation)"
        subtitle="รวมทุกสัญญาณ (WAF, Bot, Rate Limit, Threat Intel, API) เป็นคะแนนเดียวต่อ request แทนที่จะดูแยกกันทีละระบบ"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="Unified Risk Score (WAAP Consolidation)" />
      <Badge color="purple">ENTERPRISE TIER</Badge>

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> ตอนนี้ระบบมีหลายระบบตรวจจับแยกกันอยู่แล้ว (WAF rule, rate limit, bot/CAPTCHA shield,
          BOLA guard, threat intel ข้าม tenant ที่เพิ่งสร้าง) แต่ละอันให้ผลลัพธ์แยกกัน แอดมินต้องเปิดหลายหน้าดู ฟีเจอร์นี้
          รวมทุกสัญญาณเป็น "คะแนนความเสี่ยงเดียว" ต่อ request/session ให้เห็นภาพเดียวจบ
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> ทุกระบบที่มีอยู่แล้วส่งสัญญาณของตัวเองเข้ากลาง (WAF match=90, bot score=70,
          rate-limit breach=85 ฯลฯ) ถ่วงน้ำหนักตาม config ที่ปรับได้ รวมเป็นคะแนน 0-100 ต่อ request ถ้าคะแนนเกิน threshold
          ที่ตั้งไว้ ทำ action อัตโนมัติ (challenge/block/log) การเปลี่ยนน้ำหนักแต่ละสัญญาณทำได้จาก UI เดียว ไม่ต้องไปแก้
          rule 5 ที่แยกกัน
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> ลดเวลาที่ admin ต้อง cross-reference หลายหน้าจอเวลาสืบสวน incident (ตอนนี้ต้องเปิด
          Alerts + Rate Limiting + CDN + Threat Intel แยกกันเพื่อประกอบภาพเดียว) และลด false positive เพราะตัดสินใจจาก
          หลายสัญญาณรวมกัน ไม่ใช่สัญญาณเดียวที่อาจผิดพลาดได้
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> เทรนด์ตลาดปี 2026 ชัดเจนว่า "standalone WAF ตายแล้ว" -- ลูกค้าคาดหวัง WAF, bot
          management, API security, DDoS protection ให้มาเป็นแพลตฟอร์มเดียว (WAAP) ไม่ใช่เครื่องมือแยกที่ต้องต่อกันเอง
          ระบบนี้มีทุกองค์ประกอบของ WAAP อยู่แล้วจริง (WAF+Bot+API+RateLimit+ThreatIntel) สิ่งที่ขาดคือ "ชั้นรวมคะแนน"
          ที่ทำให้มันดูเหมือนแพลตฟอร์มเดียวจริงๆ ไม่ใช่ระบบแยกที่บังเอิญอยู่ด้วยกัน
        </p>
      </div>

      <div className="dash-card p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
            <Gauge size={15} className="text-purple-500" /> Request ตัวอย่าง -- คะแนนรวม
          </h3>
          <div className="text-right">
            <div className="text-[24px] font-bold font-mono text-red-500">{totalScore}</div>
            <div className="text-[9px] text-[var(--text-muted)] font-mono">/100 -- HIGH RISK</div>
          </div>
        </div>
        <div className="space-y-2">
          {SIGNAL_ROWS.map((r) => (
            <div key={r.source} className="flex items-center gap-3">
              <div className="w-32 shrink-0 text-[11px] font-mono font-semibold">{r.source}</div>
              <div className="flex-1 h-2 rounded-full bg-[var(--bg-border)] overflow-hidden">
                <div
                  className={`h-full rounded-full ${r.score >= 75 ? 'bg-red-500' : r.score >= 50 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                  style={{ width: `${r.score}%` }}
                />
              </div>
              <div className="w-10 shrink-0 text-[10.5px] font-mono text-[var(--text-muted)] text-right">{r.weight}</div>
            </div>
          ))}
        </div>
        <div className="text-[10.5px] font-mono text-[var(--text-muted)] space-y-1">
          {SIGNAL_ROWS.map((r) => (
            <div key={r.source}>
              <span className="font-semibold">{r.source}:</span> {r.value}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default UnifiedRiskScore
