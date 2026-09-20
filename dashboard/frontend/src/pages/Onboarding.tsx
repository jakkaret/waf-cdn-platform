import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { createOrigin } from '../api/origins'
import { createDomain, verifyDomain, getDomains } from '../api/domains'
import { onboardingApi } from '../api/onboarding'
import { api } from '../api/axios'
import { buildTunnelCommands } from '../lib/tunnelCommands'
import toast from 'react-hot-toast'
import {
  Server,
  Globe,
  CheckCircle2,
  ArrowRight,
  Copy,
  Check,
  RotateCw,
  ExternalLink,
  Info,
  Terminal,
} from 'lucide-react'

// Must match services/dynamodb...api/domains.py's WAF_OWN_WILDCARD_DOMAIN
// default ("waf-it-kku.online") -- only used here to preview the suggested
// subdomain before submitting; the backend is the actual source of truth
// for whether a given name auto-verifies.
const OWN_WILDCARD_SUFFIX = 'waf-it-kku.online'

type WizardStep = 1 | 2 | 3 | 4

const STEP_LABELS: Record<WizardStep, string> = {
  1: 'Create Origin',
  2: 'Connect a Domain',
  3: 'Install Agent (optional)',
  4: 'Done',
}

export const Onboarding: React.FC = () => {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [step, setStep] = useState<WizardStep>(1)
  const [originId, setOriginId] = useState<string | null>(null)
  const [domainId, setDomainId] = useState<string | null>(null)
  const [domainName, setDomainName] = useState<string | null>(null)

  // Origin form
  const [label, setLabel] = useState('')
  const [ip, setIp] = useState('')
  const [port, setPort] = useState(3000)

  // Domain form
  const [domainMode, setDomainMode] = useState<'subdomain' | 'custom'>('subdomain')
  const [subdomainLabel, setSubdomainLabel] = useState('')
  const [customDomain, setCustomDomain] = useState('')
  const [dnsInstructions, setDnsInstructions] = useState<{
    cname_record: { name: string; value: string }
    txt_record: { name: string; value: string }
  } | null>(null)
  const [verifying, setVerifying] = useState(false)

  // Resume where the user left off, on first load only.
  const { data: existingStatus } = useQuery({
    queryKey: ['onboarding-status-initial'],
    queryFn: onboardingApi.getStatus,
    refetchOnMount: 'always',
  })
  useEffect(() => {
    if (!existingStatus) return
    if (existingStatus.next_step === 'add_domain' || existingStatus.next_step === 'verify_domain') {
      setStep(2)
    } else if (existingStatus.next_step === 'done') {
      setStep(4)
    }
    // 'create_origin' -> stay on step 1, the default.
  }, [existingStatus])

  const createOriginMutation = useMutation({
    mutationFn: () => createOrigin({ label: label.trim(), ip: ip.trim(), port }),
    onSuccess: (res) => {
      const id = (res.data as any).origin_id || (res.data as any).id
      setOriginId(id)
      toast.success('สร้าง Origin แล้ว')
      setStep(2)
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'สร้าง Origin ไม่สำเร็จ'),
  })

  const createDomainMutation = useMutation({
    mutationFn: (name: string) => createDomain(originId as string, { domain_name: name }),
    onSuccess: (res) => {
      const { domain, dns_instructions, auto_verified } = res.data
      setDomainId(domain.domain_id)
      setDomainName(domain.domain_name)
      if (auto_verified) {
        toast.success('ผูกโดเมนสำเร็จ -- ใช้ subdomain ของเราเอง ไม่ต้องตั้ง DNS อะไรเพิ่ม')
        setStep(3)
      } else {
        setDnsInstructions(dns_instructions)
        toast.success('สร้างโดเมนแล้ว -- ตั้งค่า DNS ตามด้านล่างแล้วกดยืนยัน')
      }
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'เพิ่มโดเมนไม่สำเร็จ'),
  })

  const handleVerify = async () => {
    if (!originId || !domainId) return
    setVerifying(true)
    try {
      const res = await verifyDomain(originId, domainId)
      if (res.data.status === 'verified') {
        toast.success('DNS ยืนยันสำเร็จ!')
        setStep(3)
      } else {
        toast.error('ยังตรวจไม่พบ DNS record -- รอ propagate สักครู่แล้วลองใหม่ (อาจใช้เวลาถึง 30 นาที)')
      }
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'ตรวจสอบไม่สำเร็จ')
    } finally {
      setVerifying(false)
    }
  }

  const finish = () => {
    queryClient.invalidateQueries({ queryKey: ['origins'] })
    setStep(4)
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in pb-16">
      <TopBar
        title="Get Started"
        subtitle="ตั้งค่า origin แรกของคุณให้เสร็จใน 3 ขั้นตอน"
        badge={<Badge color="brand">{STEP_LABELS[step]}</Badge>}
      />

      {/* Progress dots */}
      <div className="flex items-center gap-2 px-1">
        {([1, 2, 3, 4] as WizardStep[]).map((s) => (
          <React.Fragment key={s}>
            <div
              className={`w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-mono font-bold shrink-0 ${
                s < step
                  ? 'bg-emerald-500 text-white'
                  : s === step
                  ? 'bg-orange-500 text-white'
                  : 'bg-[var(--bg-surface-elevated)] text-[var(--text-muted)] border border-[var(--bg-border)]'
              }`}
            >
              {s < step ? <Check size={13} /> : s}
            </div>
            {s < 4 && <div className={`flex-1 h-[2px] ${s < step ? 'bg-emerald-500' : 'bg-[var(--bg-border)]'}`} />}
          </React.Fragment>
        ))}
      </div>

      {/* Step 1: Create Origin */}
      {step === 1 && (
        <div className="dash-card p-5 sm:p-6 space-y-5">
          <div>
            <h3 className="text-[14.5px] font-bold font-mono m-0 mb-1 flex items-center gap-2">
              <Server size={16} className="text-orange-500" />
              1. สร้าง Origin ของคุณ
            </h3>
            <p className="text-[12px] text-[var(--text-muted)] m-0">
              Origin คือปลายทางจริงที่เว็บของคุณรันอยู่ (IP + port) -- WAF จะยืนอยู่หน้านี้ กรองการโจมตีก่อนส่งต่อให้จริง
            </p>
          </div>

          <div className="space-y-3">
            <div>
              <label className="text-[11px] font-mono font-bold text-[var(--text-secondary)] uppercase tracking-wider">
                ชื่อ (สำหรับให้คุณจำได้เอง)
              </label>
              <input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="เช่น My Shop Backend"
                className="mt-1 w-full px-3 py-2 rounded-md bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[13px] font-mono"
              />
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="text-[11px] font-mono font-bold text-[var(--text-secondary)] uppercase tracking-wider">
                  IP ปลายทาง
                </label>
                <input
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  placeholder="203.0.113.10"
                  className="mt-1 w-full px-3 py-2 rounded-md bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[13px] font-mono"
                />
              </div>
              <div>
                <label className="text-[11px] font-mono font-bold text-[var(--text-secondary)] uppercase tracking-wider">
                  Port
                </label>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(Number(e.target.value))}
                  className="mt-1 w-full px-3 py-2 rounded-md bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[13px] font-mono"
                />
              </div>
            </div>
          </div>

          <Button
            variant="brand"
            disabled={!label.trim() || !ip.trim() || createOriginMutation.isPending}
            onClick={() => createOriginMutation.mutate()}
          >
            {createOriginMutation.isPending ? 'กำลังสร้าง...' : 'ต่อไป'} <ArrowRight size={14} />
          </Button>
        </div>
      )}

      {/* Step 2: Domain */}
      {step === 2 && (
        <div className="dash-card p-5 sm:p-6 space-y-5">
          <div>
            <h3 className="text-[14.5px] font-bold font-mono m-0 mb-1 flex items-center gap-2">
              <Globe size={16} className="text-orange-500" />
              2. ผูกโดเมน
            </h3>
            <p className="text-[12px] text-[var(--text-muted)] m-0">
              เลือกได้ 2 แบบ -- ใช้ subdomain ของเรา (เสร็จทันที ไม่ต้องตั้ง DNS) หรือใช้โดเมนของคุณเอง (ต้องตั้ง DNS 2 record)
            </p>
          </div>

          {!domainName ? (
            <>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => setDomainMode('subdomain')}
                  className={`p-3.5 rounded-lg border text-left transition-colors ${
                    domainMode === 'subdomain'
                      ? 'border-orange-500 bg-orange-500/5'
                      : 'border-[var(--bg-border)] hover:bg-[var(--bg-hover)]'
                  }`}
                >
                  <div className="font-mono font-bold text-[12.5px]">ใช้ subdomain ของเรา</div>
                  <div className="text-[10.5px] text-[var(--text-muted)] font-mono mt-0.5">เสร็จทันที ไม่ต้องตั้งอะไร</div>
                </button>
                <button
                  type="button"
                  onClick={() => setDomainMode('custom')}
                  className={`p-3.5 rounded-lg border text-left transition-colors ${
                    domainMode === 'custom'
                      ? 'border-orange-500 bg-orange-500/5'
                      : 'border-[var(--bg-border)] hover:bg-[var(--bg-hover)]'
                  }`}
                >
                  <div className="font-mono font-bold text-[12.5px]">ใช้โดเมนของฉันเอง</div>
                  <div className="text-[10.5px] text-[var(--text-muted)] font-mono mt-0.5">ต้องตั้ง CNAME + TXT</div>
                </button>
              </div>

              {domainMode === 'subdomain' ? (
                <div className="space-y-2">
                  <label className="text-[11px] font-mono font-bold text-[var(--text-secondary)] uppercase tracking-wider">
                    เลือกชื่อ subdomain
                  </label>
                  <div className="flex items-center gap-1.5 font-mono text-[13px]">
                    <input
                      value={subdomainLabel}
                      onChange={(e) => setSubdomainLabel(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
                      placeholder="myshop"
                      className="flex-1 px-3 py-2 rounded-md bg-[var(--bg-primary)] border border-[var(--bg-border)]"
                    />
                    <span className="text-[var(--text-muted)]">.{OWN_WILDCARD_SUFFIX}</span>
                  </div>
                  <Button
                    variant="brand"
                    disabled={!subdomainLabel.trim() || createDomainMutation.isPending}
                    onClick={() => createDomainMutation.mutate(`${subdomainLabel.trim()}.${OWN_WILDCARD_SUFFIX}`)}
                  >
                    {createDomainMutation.isPending ? 'กำลังผูก...' : 'ผูกโดเมนนี้'}
                  </Button>
                </div>
              ) : (
                <div className="space-y-2">
                  <label className="text-[11px] font-mono font-bold text-[var(--text-secondary)] uppercase tracking-wider">
                    โดเมนของคุณ
                  </label>
                  <input
                    value={customDomain}
                    onChange={(e) => setCustomDomain(e.target.value.toLowerCase())}
                    placeholder="shop.example.com"
                    className="w-full px-3 py-2 rounded-md bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[13px] font-mono"
                  />
                  <Button
                    variant="brand"
                    disabled={!customDomain.trim() || createDomainMutation.isPending}
                    onClick={() => createDomainMutation.mutate(customDomain.trim())}
                  >
                    {createDomainMutation.isPending ? 'กำลังสร้าง...' : 'สร้างโดเมนนี้'}
                  </Button>
                </div>
              )}
            </>
          ) : dnsInstructions ? (
            <div className="space-y-3">
              <div className="p-3.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] space-y-2 font-mono text-[11.5px]">
                <div>
                  <span className="text-[var(--text-muted)]">CNAME</span> {dnsInstructions.cname_record.name} →{' '}
                  <span className="font-bold">{dnsInstructions.cname_record.value}</span>
                </div>
                <div>
                  <span className="text-[var(--text-muted)]">TXT</span> {dnsInstructions.txt_record.name} →{' '}
                  <span className="font-bold">{dnsInstructions.txt_record.value}</span>
                </div>
              </div>
              <p className="text-[11px] text-[var(--text-muted)] font-mono">
                ตั้งค่า 2 record นี้ที่ DNS provider ของคุณ แล้วรอ propagate (มักใช้เวลาไม่กี่นาที ถึง 30 นาที) แล้วกดยืนยัน
              </p>
              <Button variant="brand" disabled={verifying} onClick={handleVerify}>
                {verifying ? 'กำลังตรวจสอบ...' : 'ยืนยัน DNS'}
              </Button>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-mono text-[13px]">
              <CheckCircle2 size={16} /> ผูกโดเมนสำเร็จ
            </div>
          )}
        </div>
      )}

      {/* Step 3: optional tunnel agent */}
      {step === 3 && originId && domainName && (
        <TunnelAgentStep domain={domainName} localPort={port} onSkip={finish} onDone={finish} />
      )}

      {/* Step 4: Done */}
      {step === 4 && (
        <div className="dash-card p-8 text-center space-y-4">
          <CheckCircle2 size={40} className="mx-auto text-emerald-500" />
          <h3 className="text-[15px] font-bold font-mono m-0">ตั้งค่าเสร็จแล้ว!</h3>
          <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
            Origin ของคุณพร้อมรับ traffic ผ่าน WAF แล้ว
          </p>
          <div className="flex items-center justify-center gap-2">
            <Button variant="brand" onClick={() => navigate(originId ? `/origins/${originId}` : '/origins')}>
              ไปดู Origin ของฉัน <ExternalLink size={13} />
            </Button>
          </div>
        </div>
      )}

      {/* About this wizard */}
      <div className="dash-card p-4 text-[11px] font-mono text-[var(--text-secondary)] leading-relaxed flex items-start gap-2">
        <Info size={13} className="text-sky-500 shrink-0 mt-0.5" />
        <p className="m-0">
          ตัวช่วยตั้งค่านี้แค่เรียกใช้ API เดิมที่มีอยู่แล้วเรียงตามลำดับ (สร้าง Origin → ผูกโดเมน → ยืนยัน → ติดตั้ง agent) --
          ไม่มีอะไรใหม่ที่ทำไม่ได้อยู่แล้วผ่านหน้า Origins/Domains ปกติ แค่รวมเป็นขั้นตอนเดียวให้เริ่มง่ายขึ้น
        </p>
      </div>
    </div>
  )
}

const TunnelAgentStep: React.FC<{ domain: string; localPort: number; onSkip: () => void; onDone: () => void }> = ({
  domain,
  localPort,
  onSkip,
  onDone,
}) => {
  const [fetchEnabled, setFetchEnabled] = useState(false)
  const [copied, setCopied] = useState(false)

  // The install command embeds a real, domain-scoped, 365-day tunnel token
  // that only the backend can mint. Never cached beyond this component's
  // life (gcTime: 0), never prefetched, only fetched on an explicit click --
  // reviewed deliberately before writing this (overnight session,
  // advisor call): a long-lived credential sitting in react-query's cache
  // or localStorage would be worse than the 60-minute-expiry bug fixed
  // earlier this session, not better.
  const { data: configData, isFetching } = useQuery({
    queryKey: ['onboarding-tunnel-config', domain],
    queryFn: () =>
      api
        .get('/tunnels/config-generator', { params: { domain, port: localPort, local_ip: '127.0.0.1', platform: 'linux' } })
        .then((r) => r.data),
    enabled: fetchEnabled,
    gcTime: 0,
    staleTime: 0,
    refetchOnWindowFocus: false,
  })
  const cmds = buildTunnelCommands(configData)

  const handleCopy = () => {
    if (!cmds?.linux) return
    navigator.clipboard.writeText(cmds.linux)
    setCopied(true)
    toast.success('คัดลอกแล้ว')
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="dash-card p-5 sm:p-6 space-y-5">
      <div>
        <h3 className="text-[14.5px] font-bold font-mono m-0 mb-1 flex items-center gap-2">
          <Terminal size={16} className="text-orange-500" />
          3. ติดตั้ง Tunnel Agent (ไม่บังคับ)
        </h3>
        <p className="text-[12px] text-[var(--text-muted)] m-0">
          ถ้า origin ของคุณอยู่หลัง NAT/firewall เข้าจาก internet ตรงๆ ไม่ได้ ให้ติดตั้ง agent ตัวนี้บนเครื่อง origin เพื่อเปิด tunnel
          ออกมาหาเราแทน ถ้า IP ของคุณเข้าถึงได้จาก internet อยู่แล้ว ข้ามขั้นนี้ได้เลย
        </p>
      </div>

      {!fetchEnabled ? (
        <div className="flex items-center gap-2">
          <Button variant="brand" onClick={() => setFetchEnabled(true)}>
            สร้างคำสั่งติดตั้ง
          </Button>
          <Button variant="ghost" onClick={onSkip}>
            ข้ามขั้นนี้
          </Button>
        </div>
      ) : isFetching ? (
        <div className="flex items-center gap-2 text-[12px] text-[var(--text-muted)] font-mono">
          <RotateCw size={14} className="animate-spin" /> กำลังสร้างคำสั่ง (เฉพาะของคุณ ใช้ครั้งเดียว)...
        </div>
      ) : cmds?.linux ? (
        <div className="space-y-3">
          <div className="relative">
            <pre className="p-3.5 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[11px] font-mono overflow-x-auto whitespace-pre-wrap break-all">
              {cmds.linux}
            </pre>
            <button
              type="button"
              onClick={handleCopy}
              className="absolute top-2 right-2 p-1.5 rounded-md bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] hover:bg-[var(--bg-hover)]"
            >
              {copied ? <Check size={13} className="text-emerald-500" /> : <Copy size={13} />}
            </button>
          </div>
          <p className="text-[10.5px] text-[var(--text-muted)] font-mono">
            รันคำสั่งนี้บนเครื่อง origin ของคุณ (ต้องมี sudo) -- คำสั่งนี้มี token เฉพาะของคุณ อย่าแชร์ให้คนอื่น
          </p>
          <Button variant="brand" onClick={onDone}>
            ติดตั้งแล้ว -- เสร็จสิ้น <ArrowRight size={14} />
          </Button>
        </div>
      ) : (
        <p className="text-[12px] text-red-500 font-mono">สร้างคำสั่งไม่สำเร็จ ลองใหม่อีกครั้ง</p>
      )}
    </div>
  )
}

export default Onboarding
