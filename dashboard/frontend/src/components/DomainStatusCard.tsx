import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Check, Copy, Loader2, Circle, MinusCircle, Trash2, ChevronDown, ChevronRight, ShieldCheck } from 'lucide-react'
import { api } from '../api/axios'
import { Button } from './ui/Button'
import { Badge } from './ui/Badge'
import type { ConnectionMode, ProgressDomain } from '../api/onboarding'
import { buildTunnelCommands } from '../lib/tunnelCommands'
import { dnsCheck, connectionCheck, httpsCheck, CheckView } from '../lib/connectProgress'

// One card per domain on the origin's Domains tab: the three things that must
// be true before visitors reach the site through the WAF -- DNS points at us,
// the origin is connected, HTTPS works -- each checked by the backend
// (GET /api/onboarding/progress), with the fix shown only for what is still
// missing. Replaces the old domain list + "Verify DNS" button and the
// separate SSL Certificates tab, which listed the same domains again.

const CopyField: React.FC<{ label: string; value: string }> = ({ label, value }) => {
  const [copied, setCopied] = useState(false)
  return (
    <div className="flex items-center gap-2 min-w-0">
      <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] w-14 shrink-0">{label}</span>
      <code className="flex-1 min-w-0 truncate px-2 py-1 rounded bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[11.5px]">{value}</code>
      <button
        type="button"
        title="คัดลอก"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value)
            setCopied(true)
            setTimeout(() => setCopied(false), 1500)
          } catch {
            toast.error('คัดลอกไม่สำเร็จ')
          }
        }}
        className="shrink-0 p-1.5 rounded-md border border-[var(--bg-border)] text-[var(--text-muted)] hover:text-orange-500 cursor-pointer"
      >
        {copied ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
      </button>
    </div>
  )
}

const StateIcon: React.FC<{ state: CheckView['state'] }> = ({ state }) => {
  if (state === 'done') return <Check size={15} className="text-emerald-500 shrink-0" />
  if (state === 'waiting') return <Loader2 size={15} className="text-amber-500 animate-spin shrink-0" />
  if (state === 'blocked') return <Circle size={15} className="text-[var(--text-muted)] shrink-0" />
  return <MinusCircle size={15} className="text-[var(--text-muted)] shrink-0" />
}

const AgentCommand: React.FC<{ domain: string; port: number }> = ({ domain, port }) => {
  const [enabled, setEnabled] = useState(false)
  // The command embeds a 90-day, domain-scoped tunnel token: mint it only
  // on an explicit click and never keep it cached (same rule as Tunnels.tsx).
  const { data, isFetching, isError } = useQuery({
    queryKey: ['agent-command', domain, port],
    queryFn: () =>
      api.get('/tunnels/config-generator', { params: { domain, port, local_ip: '127.0.0.1', platform: 'linux' } }).then((r) => r.data),
    enabled,
    gcTime: 0,
    staleTime: 0,
    refetchOnWindowFocus: false,
  })
  const cmds = buildTunnelCommands(data)
  if (!enabled) {
    return (
      <Button variant="secondary" size="sm" onClick={() => setEnabled(true)}>
        แสดงคำสั่งติดตั้ง Agent
      </Button>
    )
  }
  if (isFetching) return <p className="text-[11.5px] text-[var(--text-muted)] m-0">กำลังสร้างคำสั่ง (เฉพาะโดเมนนี้)...</p>
  if (isError || !cmds) return <p className="text-[11.5px] text-red-500 m-0">สร้างคำสั่งไม่สำเร็จ ลองใหม่อีกครั้ง</p>
  return (
    <div className="space-y-1.5">
      <CopyField label="Linux" value={cmds.linux} />
      {cmds.docker && <CopyField label="Docker" value={cmds.docker} />}
      <p className="text-[10.5px] text-[var(--text-muted)] m-0">
        รันบนเครื่องที่เว็บรันอยู่ (port {port}) — คำสั่งมี token ของโดเมนนี้ อย่าแชร์ต่อ · ต้องออก internet ไปที่พอร์ต 7000 ได้
      </p>
    </div>
  )
}

interface DomainStatusCardProps {
  item: ProgressDomain
  mode: ConnectionMode | null
  originPort: number
  egressIps: string[]
  canEdit: boolean
  // Agent tokens are minted for the domain's owner or a platform admin only
  // (/tunnels/config-generator), not for origin editors.
  canMintAgent: boolean
  onRemove: (domainId: string) => void
}

export const DomainStatusCard: React.FC<DomainStatusCardProps> = ({ item, mode, originPort, egressIps, canEdit, canMintAgent, onRemove }) => {
  const [showTxt, setShowTxt] = useState(false)
  const dns = dnsCheck(item)
  const conn = connectionCheck(item, mode)
  const https = httpsCheck(item)
  const rec = item.dns.instructions

  const row = (check: CheckView, body?: React.ReactNode) => (
    <div className="py-2.5 border-t border-[var(--bg-border-subtle)] first:border-t-0">
      <div className="flex items-start gap-2.5">
        <StateIcon state={check.state} />
        <div className="min-w-0 flex-1">
          <p className="m-0 text-[12.5px]">
            <span className="font-bold text-[var(--text-primary)]">{check.label}</span>{' '}
            <span className="text-[var(--text-secondary)]">{check.detail}</span>
          </p>
          {check.state !== 'done' && body && <div className="mt-2 space-y-2">{body}</div>}
        </div>
      </div>
    </div>
  )

  return (
    <div className="dash-card p-4 sm:p-5 font-mono">
      <div className="flex items-start justify-between gap-3 mb-1">
        <div className="flex items-center gap-2.5 min-w-0">
          <h3 className="text-[15px] font-bold text-[var(--text-primary)] m-0 truncate">{item.domain_name}</h3>
          <Badge color={item.ready ? 'success' : 'warning'} size="sm">{item.ready ? 'LIVE' : 'SETTING UP'}</Badge>
        </div>
        {canEdit && (
          <Button variant="ghost" size="sm" onClick={() => onRemove(item.domain_id)} icon={<Trash2 size={13} />} title="Remove domain">
            <span className="sr-only">Remove</span>
          </Button>
        )}
      </div>

      {row(
        dns,
        <>
          <p className="m-0 text-[11.5px] text-[var(--text-muted)]">
            ที่ผู้ให้บริการ DNS ของคุณ: ลบ A record เดิมของชื่อนี้ (ถ้ามี) แล้วเพิ่ม 1 record
          </p>
          <CopyField label="Type" value={rec.cname_record.type} />
          <CopyField label="Name" value={rec.cname_record.name} />
          <CopyField label="Target" value={rec.cname_record.value} />
          {rec.txt_record.value && <button
            type="button"
            onClick={() => setShowTxt((v) => !v)}
            className="flex items-center gap-1 text-[11px] text-[var(--text-muted)] hover:text-orange-500 cursor-pointer"
          >
            {showTxt ? <ChevronDown size={12} /> : <ChevronRight size={12} />} ตั้ง CNAME ไม่ได้? (โดเมนหลักไม่มี sub หรือใช้ proxy ของ CDN อื่น)
          </button>}
          {showTxt && rec.txt_record.value && (
            <div className="space-y-1.5 pl-1">
              <p className="m-0 text-[11px] text-[var(--text-muted)]">
                ยืนยันความเป็นเจ้าของด้วย TXT แทน แล้วชี้ชื่อนี้มาที่ {rec.cname_record.value} ด้วย ALIAS / ANAME / CNAME flattening
                ถ้าผู้ให้บริการรองรับ (ถ้าใช้ Cloudflare ให้ปิด proxy เป็นเมฆสีเทา)
              </p>
              <CopyField label="TXT" value={rec.txt_record.name} />
              <CopyField label="Value" value={rec.txt_record.value} />
            </div>
          )}
        </>
      )}
      {row(
        conn,
        mode === 'agent' && item.connection.status === 'waiting_agent' ? (
          canMintAgent ? (
            <AgentCommand domain={item.domain_name} port={originPort} />
          ) : (
            <p className="m-0 text-[11px] text-[var(--text-muted)]">เจ้าของ origin เป็นผู้สร้างคำสั่งติดตั้ง Agent</p>
          )
        ) : undefined
      )}
      {row(https)}

      {item.ready && mode === 'direct' && (
        <div className="mt-2 p-2.5 rounded-lg border border-sky-500/25 bg-sky-500/5 text-[11px] text-[var(--text-secondary)] flex gap-2">
          <ShieldCheck size={14} className="text-sky-500 shrink-0 mt-0.5" />
          <span>
            แนะนำ: IP เดิมของเซิร์ฟเวอร์อาจยังถูกยิงตรงได้ (ข้าม WAF) ตั้ง firewall ให้รับ HTTP/HTTPS
            {egressIps.length ? ` เฉพาะจาก ${egressIps.join(', ')}` : ' เฉพาะจาก IP ของ WAF'} หรือเปลี่ยนไปใช้ Agent ซึ่งไม่ต้องเปิดพอร์ต
          </span>
        </div>
      )}
    </div>
  )
}

export default DomainStatusCard
