import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Braces, Info, ArrowLeft, AlertTriangle } from 'lucide-react'

const SAMPLE_ENDPOINTS = [
  { path: 'GET /api/v1/orders/{id}', discovered: 'auto จาก traffic จริง', risk: 'ปกติ', note: 'ID เป็นเลขเรียง -- เสี่ยง IDOR ถ้าไม่เช็ค ownership' },
  { path: 'POST /graphql', discovered: 'auto จาก traffic จริง', risk: 'สูง', note: 'introspection query เปิดอยู่ -- เห็น schema ทั้งหมดจาก client ไหนก็ได้' },
  { path: 'GET /api/v1/users/export', discovered: 'auto จาก traffic จริง', risk: 'สูง', note: 'ไม่มีใน API docs ที่ประกาศไว้ -- "shadow endpoint" ที่ทีมอาจลืมปิด' },
]

const RISK_COLOR: Record<string, 'success' | 'warning' | 'danger'> = { ปกติ: 'success', สูง: 'danger' }

export const ApiSchemaGuard: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="API / GraphQL Schema-Aware Protection"
        subtitle="เว็บยุคนี้เป็น API-first -- ป้องกันแบบเดารูปแบบ URL ไม่พออีกแล้ว ต้องเข้าใจ schema จริง"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="API / GraphQL Schema-Aware Protection" />

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> เว็บยุคนี้ส่วนใหญ่เป็น SPA/mobile app ที่คุยกับ backend ผ่าน REST/GraphQL API ล้วนๆ
          ไม่ใช่หน้า HTML แบบเดิม ปัญหาความปลอดภัยที่แท้จริงเลยย้ายจาก "SQLi ใน form" ไปเป็น "IDOR", "excessive data exposure",
          "GraphQL introspection abuse", "shadow/zombie endpoint ที่ทีมลืมปิด" -- ของที่ WAF ทั่วไปดักไม่ถึง เพราะ WAF
          ทั่วไปมองแค่ pattern ของ payload ไม่เข้าใจ "โครงสร้าง" ของ API จริง
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> auto-discover endpoint จาก traffic จริงที่วิ่งผ่าน (ไม่ต้องพึ่ง OpenAPI/GraphQL
          schema ที่ทีมอาจไม่ได้อัปเดต) จัดกลุ่มตาม path pattern จริง (ระบบมี tenant/domain pattern matching อยู่แล้ว
          ใน services/tenant_service.py ต่อยอดตรงนี้ได้) ตรวจจับ: endpoint ที่ response ข้อมูลเยอะผิดปกติ (excessive
          exposure), ID ที่เรียงเป็นเลข (เสี่ยง IDOR), endpoint ที่ไม่เคยประกาศแต่มี traffic จริง (shadow endpoint),
          GraphQL introspection query ที่เปิดสู่สาธารณะ
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> เจอความเสี่ยงที่ scanner แบบเดิมมองไม่เห็นเลย เพราะ scanner ทั่วไปสแกนจาก URL ที่รู้จัก
          ไม่รู้ว่า endpoint ไหนมีอยู่จริงบ้างถ้าไม่มี documentation ที่อัปเดต -- ระบบนี้เห็นจาก traffic จริง ไม่ต้องพึ่งเอกสาร
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> OWASP API Security Top 10 (BOLA/IDOR เป็นอันดับ 1 ต่อเนื่องหลายปี) คือสิ่งที่ WAF
          แบบ signature-based (ModSecurity/CRS ล้วนๆ) แทบไม่แตะเลย ระบบนี้มี "BOLA guard" อยู่แล้วเป็นจุดขาย (ตามที่เอกสาร
          ประเมินเดิมพูดถึง) ฟีเจอร์นี้คือขยายจากจุดนั้นให้ครอบคลุม API ทั้งหมดอัตโนมัติ ไม่ใช่แค่จุดที่เขียน rule ไว้ล่วงหน้า
        </p>
      </div>

      <div className="dash-card p-5 space-y-3">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <Braces size={15} className="text-purple-500" /> Endpoint ที่ auto-discover ได้ (ตัวอย่าง)
        </h3>
        <div className="space-y-2">
          {SAMPLE_ENDPOINTS.map((e) => (
            <div key={e.path} className="p-3.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono font-bold text-[12px]">{e.path}</span>
                <Badge color={RISK_COLOR[e.risk] || 'gray'}>
                  {e.risk === 'สูง' && <AlertTriangle size={11} />} Risk: {e.risk}
                </Badge>
              </div>
              <div className="text-[10.5px] text-[var(--text-muted)] font-mono">{e.discovered}</div>
              <div className="text-[11px] text-[var(--text-secondary)] font-mono">{e.note}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default ApiSchemaGuard
