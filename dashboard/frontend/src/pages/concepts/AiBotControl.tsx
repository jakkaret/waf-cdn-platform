import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Bot, Info, ArrowLeft, Ban, Check, DollarSign } from 'lucide-react'

const SAMPLE_BOTS = [
  { name: 'GPTBot (OpenAI)', purpose: 'เก็บข้อมูลเทรน AI', hits24h: 4210, policy: 'allow', revenue: null },
  { name: 'ClaudeBot (Anthropic)', purpose: 'เก็บข้อมูลเทรน AI', hits24h: 3105, policy: 'allow', revenue: null },
  { name: 'Bytespider (TikTok)', purpose: 'เก็บข้อมูลเทรน AI', hits24h: 8850, policy: 'block', revenue: null },
  { name: 'Perplexity-User', purpose: 'ดึงข้อมูลตอบ user แบบ real-time', hits24h: 1920, policy: 'monetize', revenue: '$0.002/req' },
  { name: 'Unknown scraper (12 IP)', purpose: 'ไม่ระบุตัวตน, headless browser pattern', hits24h: 15400, policy: 'challenge', revenue: null },
]

const POLICY_META: Record<string, { color: 'success' | 'danger' | 'warning' | 'brand'; label: string }> = {
  allow: { color: 'success', label: 'ALLOW' },
  block: { color: 'danger', label: 'BLOCK' },
  challenge: { color: 'warning', label: 'CHALLENGE' },
  monetize: { color: 'brand', label: 'MONETIZE' },
}

export const AiBotControl: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="AI Bot & Scraper Control"
        subtitle="แยกแยะและควบคุม bot ที่เก็บข้อมูลไปเทรน AI ทีละตัว ไม่ใช่บล็อกรวมหรือปล่อยรวม"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="AI Bot & Scraper Control" />

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> Pain point ยุคนี้จริงๆ คือ traffic จาก AI crawler (GPTBot, ClaudeBot, Bytespider ฯลฯ)
          และ scraper แบบไม่ระบุตัวตนเพิ่มขึ้นมหาศาล บางเว็บ traffic ส่วนนี้แซง human user แล้ว ฟีเจอร์นี้ไม่ใช่แค่
          "บล็อก bot ทั้งหมด" (แบบเดิม) แต่แยกแยะเป็นราย bot ให้เจ้าของเว็บเลือกเอง: allow / block / challenge / monetize
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> จับ User-Agent + behavior pattern (headless browser signature, request rate,
          ไม่รัน JS) จับคู่กับ known AI-crawler fingerprint database (อัปเดตตามผู้ให้บริการ AI แต่ละเจ้าประกาศ)
          bot ที่ไม่รู้จักเลยแต่ pattern น่าสงสัย (ไม่รัน JS, headless) เข้า challenge queue ก่อนตัดสินใจ
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> ลด bandwidth/compute cost จาก crawler ที่ไม่ได้สร้างมูลค่าให้เว็บเลย
          (ต่างจาก Googlebot ที่พาคนมาเว็บจริง) และเปิดทางเลือกใหม่ "monetize" -- คิดเงิน AI ที่ดึงข้อมูลไปใช้ real-time
          (เช่น Perplexity) แทนที่จะปล่อยฟรีหรือบล็อกทิ้งเฉยๆ
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> Cloudflare เพิ่งเปิดฟีเจอร์ทำนองนี้ (AI Labyrinth, pay-per-crawl) เป็นกระแสใหญ่ปี 2026
          เพราะเป็นปัญหาจริงที่ทุกเว็บเจอ ไม่ใช่แค่เว็บใหญ่ ระบบเรามี bot/challenge engine อยู่แล้ว (CAPTCHA/OTP Shield)
          ต่อยอดแค่เพิ่ม fingerprint database + ทางเลือก "monetize" เข้าไป
        </p>
      </div>

      <div className="dash-card p-5 space-y-3">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <Bot size={15} className="text-purple-500" /> Bot ที่ตรวจพบ 24 ชม.ล่าสุด (ตัวอย่าง)
        </h3>
        <div className="space-y-2">
          {SAMPLE_BOTS.map((b) => {
            const meta = POLICY_META[b.policy]
            return (
              <div
                key={b.name}
                className="p-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] flex items-center justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="font-mono font-semibold text-[12.5px]">{b.name}</div>
                  <div className="font-mono text-[10.5px] text-[var(--text-muted)]">{b.purpose}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10.5px] font-mono text-[var(--text-muted)]">{b.hits24h.toLocaleString()} req</span>
                  {b.revenue && (
                    <span className="mono-chip text-emerald-600 dark:text-emerald-400 font-bold flex items-center gap-1">
                      <DollarSign size={10} /> {b.revenue}
                    </span>
                  )}
                  <Badge color={meta.color}>
                    {b.policy === 'block' ? <Ban size={10} /> : b.policy === 'allow' ? <Check size={10} /> : null}
                    {meta.label}
                  </Badge>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export default AiBotControl
