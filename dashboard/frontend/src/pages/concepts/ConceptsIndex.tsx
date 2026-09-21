import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import {
  Sparkles,
  Users,
  FileText,
  ArrowRight,
  Bot,
  Bug,
  Package,
  Braces,
  DollarSign,
  Lock,
  Cpu,
  Fish,
  Gauge,
} from 'lucide-react'

type Tier = 'standard' | 'enterprise'

const CONCEPTS: { path: string; icon: any; title: string; tagline: string; from: string; tier: Tier }[] = [
  {
    path: '/concepts/ai-rules',
    icon: Sparkles,
    title: 'AI Rule Composer',
    tagline: 'ให้ AI เสนอ rule ที่ควรเพิ่มได้เลย ไม่ใช่แค่อธิบาย attack',
    from: 'ต่อยอดจุดแข็งที่มีอยู่จริง (AI Copilot + Feature Attribution)',
    tier: 'standard',
  },
  {
    path: '/concepts/team',
    icon: Users,
    title: 'Team Workspace',
    tagline: 'หลายคนดูแล origin เดียวกันได้ พร้อม audit log ว่าใครแก้อะไร',
    from: 'เอาจุดแข็งของ Cloudflare Enterprise (multi-seat, audit trail) มาปรับให้เบากว่า',
    tier: 'standard',
  },
  {
    path: '/concepts/postmortem',
    icon: FileText,
    title: 'AI Incident Postmortem',
    tagline: 'พอมี incident จริง (attack spike / downtime) ให้ AI ร่างรายงานสรุปให้อัตโนมัติ',
    from: 'ไม่มีคู่แข่งเจ้าไหนทำ -- ต่อยอด AI Copilot ที่มีอยู่แล้วให้ไปไกลกว่าการอธิบาย log',
    tier: 'standard',
  },
  {
    path: '/concepts/ai-bots',
    icon: Bot,
    title: 'AI Bot & Scraper Control',
    tagline: 'แยกแยะ AI crawler ทีละตัว allow/block/challenge/monetize ไม่ใช่บล็อกรวม',
    from: 'Pain point ยุค 2026 จริง -- traffic AI crawler แซง human user ในหลายเว็บแล้ว',
    tier: 'standard',
  },
  {
    path: '/concepts/cve-patch',
    icon: Bug,
    title: 'Auto Virtual-Patch จาก CVE Feed',
    tagline: 'CVE ใหม่ออก rule ป้องกันก็ออกให้ภายในไม่กี่ชม. ไม่ต้องรอ admin ตามข่าวเอง',
    from: 'ต่อยอด Virtual Patching ที่เป็นจุดขายเดิมอยู่แล้วให้เป็นอัตโนมัติ',
    tier: 'standard',
  },
  {
    path: '/concepts/supply-chain',
    icon: Package,
    title: 'Third-Party Script Monitor',
    tagline: 'จับ script แปลกปลอมที่ถูกฉีดเข้าหน้าเว็บแบบ Magecart ก่อนลูกค้าโดนขโมยข้อมูลบัตร',
    from: 'มุมที่ WAF ทั่วไปมองไม่ถึง (server-side อย่างเดียว) -- ดูจากฝั่ง browser จริง',
    tier: 'standard',
  },
  {
    path: '/concepts/api-guard',
    icon: Braces,
    title: 'API / GraphQL Schema-Aware Protection',
    tagline: 'auto-discover endpoint จาก traffic จริง จับ IDOR/shadow endpoint ที่เอกสารไม่มี',
    from: 'เว็บยุคนี้เป็น API-first -- ต่อยอด BOLA guard เดิมให้ครอบคลุมทั้ง API',
    tier: 'standard',
  },
  {
    path: '/concepts/cost-shield',
    icon: DollarSign,
    title: 'Attack Cost Shield',
    tagline: 'โชว์เป็นเงินจริงว่าบล็อก bot ไปประหยัดค่า cloud/bandwidth เท่าไหร่ เตือนก่อนบิลช็อก',
    from: 'เปลี่ยน WAF จาก "ความปลอดภัยนามธรรม" เป็นตัวเลขที่ผู้บริหารเข้าใจทันที',
    tier: 'standard',
  },
  // ต่อจากนี้: อิงงานวิจัย/ข่าวจริงปี 2026 (WebSearch, แหล่งอ้างอิงอยู่ในแต่ละหน้า) --
  // เทรนด์ WAF Gen 3/4 และของที่ผู้ให้บริการใหญ่เปิดตัว/กำลัง beta จริงในปีนี้
  {
    path: '/concepts/agentic-traffic',
    icon: Bot,
    title: 'Agentic Traffic Governance',
    tagline: 'แยกว่า session นี้มนุษย์คลิกเองหรือ AI agent (Atlas/Comet) กระทำการแทน แล้วตั้ง policy คนละแบบ',
    from: 'เทรนด์ปี 2026 จริงตามข้อมูล HUMAN Security/Akamai -- Cloudflare เพิ่งเปิด "Precursor" รับเรื่องนี้โดยเฉพาะ',
    tier: 'enterprise',
  },
  {
    path: '/concepts/ai-firewall',
    icon: Cpu,
    title: 'AI Firewall (LLM Gateway Protection)',
    tagline: 'ป้องกัน prompt injection/data leak/denial-of-wallet ถ้า origin มี AI feature ของตัวเอง',
    from: 'ตรงกับสินค้าจริงที่ Akamai เปิดตัวปี 2026 ("Firewall for AI") -- หมวดใหม่ที่กำลังเกิดขึ้นจริง',
    tier: 'enterprise',
  },
  {
    path: '/concepts/deception',
    icon: Fish,
    title: 'Deception Layer (Honeytokens)',
    tagline: 'วางกับดักปลอม (API key, ฟอร์ม, path) ใครแตะคือผิดปกติ 100% ไม่มี false positive',
    from: 'Deception technology เป็นเทรนด์ enterprise ที่กำลังโต ยังไม่มีคู่แข่งระดับเรานำเสนอ',
    tier: 'enterprise',
  },
  {
    path: '/concepts/quantum-tls',
    icon: Lock,
    title: 'Post-Quantum TLS Readiness',
    tagline: 'ดูว่าโดเมนไหน hybrid PQC แล้วบ้าง ป้องกัน "harvest now, decrypt later"',
    from: 'AWS/Google Cloud/F5 deploy ML-KEM จริงแล้วในปี 2025-2026 -- Fortune 500 38% เริ่ม migrate แล้ว',
    tier: 'enterprise',
  },
  {
    path: '/concepts/risk-score',
    icon: Gauge,
    title: 'Unified Risk Score (WAAP)',
    tagline: 'รวม WAF+Bot+RateLimit+ThreatIntel+API เป็นคะแนนเดียว แทนดูแยกหน้า',
    from: 'เทรนด์ตลาด 2026: "standalone WAF ตายแล้ว" ลูกค้าคาดหวัง WAAP รวมเป็นแพลตฟอร์มเดียว',
    tier: 'enterprise',
  },
]

const TIER_META: Record<Tier, { color: 'gray' | 'purple'; label: string }> = {
  standard: { color: 'gray', label: 'STANDARD' },
  enterprise: { color: 'purple', label: 'ENTERPRISE' },
}

export const ConceptsIndex: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar title="Concepts" subtitle="ไอเดียฟีเจอร์ใหม่ที่ยังไม่สร้างจริง -- ดูภาพคร่าวๆ ก่อนตัดสินใจ" />
      <ConceptBanner title="หน้ารวม Concept ทั้งหมด" />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {CONCEPTS.map((c) => {
          const Icon = c.icon
          const tierMeta = TIER_META[c.tier]
          return (
            <button
              key={c.path}
              onClick={() => navigate(c.path)}
              className="dash-card p-5 text-left space-y-3 hover:border-purple-400/50 hover:shadow-card-hover transition-all cursor-pointer group"
            >
              <div className="flex items-center justify-between">
                <div className="w-10 h-10 rounded-lg bg-purple-500/10 text-purple-500 flex items-center justify-center">
                  <Icon size={18} />
                </div>
                <Badge color={tierMeta.color}>{tierMeta.label}</Badge>
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
