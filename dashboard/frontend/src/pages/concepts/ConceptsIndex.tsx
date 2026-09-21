import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Sparkles, Users, FileText, ArrowRight, Bot, Bug, Package, Braces, DollarSign } from 'lucide-react'

const CONCEPTS = [
  {
    path: '/concepts/ai-rules',
    icon: Sparkles,
    title: 'AI Rule Composer',
    tagline: 'ให้ AI เสนอ rule ที่ควรเพิ่มได้เลย ไม่ใช่แค่อธิบาย attack',
    from: 'ต่อยอดจุดแข็งที่มีอยู่จริง (AI Copilot + Feature Attribution)',
  },
  {
    path: '/concepts/team',
    icon: Users,
    title: 'Team Workspace',
    tagline: 'หลายคนดูแล origin เดียวกันได้ พร้อม audit log ว่าใครแก้อะไร',
    from: 'เอาจุดแข็งของ Cloudflare Enterprise (multi-seat, audit trail) มาปรับให้เบากว่า',
  },
  {
    path: '/concepts/postmortem',
    icon: FileText,
    title: 'AI Incident Postmortem',
    tagline: 'พอมี incident จริง (attack spike / downtime) ให้ AI ร่างรายงานสรุปให้อัตโนมัติ',
    from: 'ไม่มีคู่แข่งเจ้าไหนทำ -- ต่อยอด AI Copilot ที่มีอยู่แล้วให้ไปไกลกว่าการอธิบาย log',
  },
  {
    path: '/concepts/ai-bots',
    icon: Bot,
    title: 'AI Bot & Scraper Control',
    tagline: 'แยกแยะ AI crawler ทีละตัว allow/block/challenge/monetize ไม่ใช่บล็อกรวม',
    from: 'Pain point ยุค 2026 จริง -- traffic AI crawler แซง human user ในหลายเว็บแล้ว',
  },
  {
    path: '/concepts/cve-patch',
    icon: Bug,
    title: 'Auto Virtual-Patch จาก CVE Feed',
    tagline: 'CVE ใหม่ออก rule ป้องกันก็ออกให้ภายในไม่กี่ชม. ไม่ต้องรอ admin ตามข่าวเอง',
    from: 'ต่อยอด Virtual Patching ที่เป็นจุดขายเดิมอยู่แล้วให้เป็นอัตโนมัติ',
  },
  {
    path: '/concepts/supply-chain',
    icon: Package,
    title: 'Third-Party Script Monitor',
    tagline: 'จับ script แปลกปลอมที่ถูกฉีดเข้าหน้าเว็บแบบ Magecart ก่อนลูกค้าโดนขโมยข้อมูลบัตร',
    from: 'มุมที่ WAF ทั่วไปมองไม่ถึง (server-side อย่างเดียว) -- ดูจากฝั่ง browser จริง',
  },
  {
    path: '/concepts/api-guard',
    icon: Braces,
    title: 'API / GraphQL Schema-Aware Protection',
    tagline: 'auto-discover endpoint จาก traffic จริง จับ IDOR/shadow endpoint ที่เอกสารไม่มี',
    from: 'เว็บยุคนี้เป็น API-first -- ต่อยอด BOLA guard เดิมให้ครอบคลุมทั้ง API',
  },
  {
    path: '/concepts/cost-shield',
    icon: DollarSign,
    title: 'Attack Cost Shield',
    tagline: 'โชว์เป็นเงินจริงว่าบล็อก bot ไปประหยัดค่า cloud/bandwidth เท่าไหร่ เตือนก่อนบิลช็อก',
    from: 'เปลี่ยน WAF จาก "ความปลอดภัยนามธรรม" เป็นตัวเลขที่ผู้บริหารเข้าใจทันที',
  },
]

export const ConceptsIndex: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar title="Concepts" subtitle="ไอเดียฟีเจอร์ใหม่ที่ยังไม่สร้างจริง -- ดูภาพคร่าวๆ ก่อนตัดสินใจ" />
      <ConceptBanner title="หน้ารวม Concept ทั้งหมด" />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {CONCEPTS.map((c) => {
          const Icon = c.icon
          return (
            <button
              key={c.path}
              onClick={() => navigate(c.path)}
              className="dash-card p-5 text-left space-y-3 hover:border-purple-400/50 hover:shadow-card-hover transition-all cursor-pointer group"
            >
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 text-purple-500 flex items-center justify-center">
                <Icon size={18} />
              </div>
              <div>
                <h3 className="font-bold text-[14px] font-mono m-0 group-hover:text-purple-500 transition-colors">
                  {c.title}
                </h3>
                <p className="text-[11.5px] text-[var(--text-muted)] font-mono m-0 mt-1">{c.tagline}</p>
              </div>
              <p className="text-[10px] text-[var(--text-muted)] font-mono m-0 italic">{c.from}</p>
              <div className="flex items-center gap-1 text-[11px] font-mono font-bold text-purple-500">
                ดูตัวอย่าง <ArrowRight size={12} />
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

export default ConceptsIndex
