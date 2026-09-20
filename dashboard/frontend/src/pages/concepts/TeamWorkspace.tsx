import React from 'react'
import { useNavigate } from 'react-router-dom'
import { TopBar } from '../../components/layout/TopBar'
import { Badge } from '../../components/ui/Badge'
import { Button } from '../../components/ui/Button'
import { ConceptBanner } from '../../components/concepts/ConceptBanner'
import { Users, Info, ArrowLeft, Shield, Eye, Wrench, Clock } from 'lucide-react'

const SAMPLE_MEMBERS = [
  { name: 'Somchai (คุณ)', email: 'somchai@company.com', role: 'Owner', avatar: 'S' },
  { name: 'Nisa', email: 'nisa@company.com', role: 'Editor', avatar: 'N' },
  { name: 'Krit', email: 'krit@company.com', role: 'Viewer', avatar: 'K' },
]

const ROLE_META: Record<string, { icon: React.ReactNode; desc: string; color: 'brand' | 'blue' | 'gray' }> = {
  Owner: { icon: <Shield size={12} />, desc: 'แก้ rule, ลบ origin, เชิญ/เอาคนออกได้', color: 'brand' },
  Editor: { icon: <Wrench size={12} />, desc: 'แก้ rule, ดู log ได้ แต่ลบ origin/เชิญคนไม่ได้', color: 'blue' },
  Viewer: { icon: <Eye size={12} />, desc: 'ดู log/dashboard อย่างเดียว แก้อะไรไม่ได้เลย', color: 'gray' },
}

const SAMPLE_AUDIT_LOG = [
  { who: 'Nisa', action: 'แก้ paranoia_level จาก 1 เป็น 2', when: '5 นาทีที่แล้ว' },
  { who: 'Somchai', action: 'เชิญ krit@company.com เข้า workspace (Viewer)', when: '2 ชม.ที่แล้ว' },
  { who: 'Nisa', action: 'เพิ่ม custom rule บล็อก /wp-admin', when: 'เมื่อวาน 14:32' },
  { who: 'Somchai', action: 'ลบ origin "staging-old"', when: '3 วันที่แล้ว' },
]

export const TeamWorkspace: React.FC = () => {
  const navigate = useNavigate()
  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <TopBar
        title="Team Workspace"
        subtitle="หลายคนดูแล origin เดียวกันได้ พร้อม role และ audit log ว่าใครแก้อะไรเมื่อไหร่"
        action={
          <Button variant="secondary" onClick={() => navigate('/concepts')}>
            <ArrowLeft size={13} /> กลับ
          </Button>
        }
      />
      <ConceptBanner title="Team Workspace" />

      <div className="dash-card p-5 space-y-3 text-[12px] font-mono leading-relaxed">
        <div className="flex items-center gap-2 font-bold text-[13.5px]">
          <Info size={15} className="text-sky-500" /> คืออะไร ทำงานยังไง ช่วยอะไร ทำไมต้องมี
        </div>
        <p className="m-0">
          <strong>คืออะไร:</strong> ตอนนี้ระบบผูก origin กับ user_id เดียว (เจ้าของคนเดียว) มี "viewer grant" ให้แชร์ดูได้อย่างเดียว
          Team Workspace คือขยายให้เป็นทีมจริง มี role 3 ระดับ (Owner/Editor/Viewer) และมี audit log ว่าใครแก้อะไรเมื่อไหร่
        </p>
        <p className="m-0">
          <strong>ทำงานยังไง:</strong> เพิ่มตาราง workspace_members (workspace_id, user_id, role) แทนที่จะผูก origin กับ user_id
          ตรงๆ ให้ผูกกับ workspace_id แทน ทุก endpoint ที่เช็ค ownership (`verify_origin_ownership`) เปลี่ยนไปเช็คผ่าน
          workspace membership + role แทน การกระทำที่เปลี่ยนแปลงข้อมูล (แก้ rule, ลบ origin, เชิญคน) เขียนลง audit_log ทุกครั้ง
        </p>
        <p className="m-0">
          <strong>ช่วยอะไร:</strong> ทีมที่มีมากกว่า 1 คนดูแล WAF ร่วมกันได้จริง (ไม่ต้องแชร์ password บัญชีเดียวกันแบบที่หลายที่ทำกันตอนนี้)
          และเมื่อมีอะไรพัง รู้ทันทีว่าใครแก้อะไรล่าสุด ไม่ต้องเดา
        </p>
        <p className="m-0">
          <strong>ทำไมต้องมี:</strong> Cloudflare/เจ้าใหญ่ทุกเจ้ามี multi-seat + audit log เป็นมาตรฐานพื้นฐานสำหรับลูกค้าระดับองค์กร
          ตอนนี้ระบบเรายังเป็น "single-admin" ทั้งที่ RBAC พื้นฐาน (owner/viewer ต่อ origin) มีอยู่แล้ว ขาดแค่ role ระดับกลาง + audit trail
        </p>
      </div>

      <div className="dash-card p-5 space-y-3">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <Users size={15} className="text-purple-500" /> สมาชิกใน workspace (ตัวอย่าง)
        </h3>
        <div className="space-y-2">
          {SAMPLE_MEMBERS.map((m) => {
            const meta = ROLE_META[m.role]
            return (
              <div
                key={m.email}
                className="p-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] flex items-center justify-between"
              >
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-full bg-purple-500/10 text-purple-500 flex items-center justify-center font-mono font-bold text-[12px]">
                    {m.avatar}
                  </div>
                  <div>
                    <div className="font-mono font-semibold text-[12.5px]">{m.name}</div>
                    <div className="font-mono text-[10.5px] text-[var(--text-muted)]">{m.email}</div>
                  </div>
                </div>
                <div className="text-right">
                  <Badge color={meta.color}>
                    {meta.icon} {m.role}
                  </Badge>
                  <div className="text-[9.5px] text-[var(--text-muted)] font-mono mt-1 max-w-[180px]">{meta.desc}</div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="dash-card p-5 space-y-3">
        <h3 className="text-[13px] font-bold font-mono m-0 flex items-center gap-2">
          <Clock size={15} className="text-purple-500" /> Audit log (ตัวอย่าง)
        </h3>
        <div className="space-y-2">
          {SAMPLE_AUDIT_LOG.map((e, i) => (
            <div key={i} className="flex items-center justify-between text-[11.5px] font-mono py-1.5 border-b border-[var(--bg-border)] last:border-0">
              <span>
                <strong>{e.who}</strong> {e.action}
              </span>
              <span className="text-[var(--text-muted)] shrink-0 ml-3">{e.when}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default TeamWorkspace
