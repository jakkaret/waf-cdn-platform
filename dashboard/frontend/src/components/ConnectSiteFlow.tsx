import React, { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Globe,
  Info,
  Pencil,
  Search,
  Server,
  Terminal,
  XCircle,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Button } from './ui/Button'
import { onboardingApi, ConnectionMode, InspectResult } from '../api/onboarding'
import { createDomain } from '../api/domains'
import { describeInspect, describeOriginAdjusted, normalizeDomainInput, InspectView } from '../lib/connectProgress'
import { useT } from '../i18n'

// One flow for every "connect a site" entry point (Origins → Add Origin, the
// Onboarding page, and Add Domain on an existing origin). It replaces the old
// AddOriginModal (label/IP/port first, domain later on another page) and
// DomainSetupWizard (4 steps, CNAME + TXT, manual verify) with:
//   domain → we look at its current DNS and probe the server → connect.
// Progress (DNS / connection / HTTPS) is then shown on the origin's
// Domains tab, which checks itself.

interface ConnectSiteFlowProps {
  // Adding another domain to an origin whose connection is already set up.
  existingOriginId?: string
  onDone: (originId: string) => void
  onCancel?: () => void
}

const HOSTNAME_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/

const TONE: Record<InspectView['tone'], { className: string; icon: LucideIcon }> = {
  success: { className: 'bg-emerald-500/10 border-emerald-500/25 text-emerald-700 dark:text-emerald-300', icon: CheckCircle2 },
  warning: { className: 'bg-amber-500/10 border-amber-500/25 text-amber-700 dark:text-amber-300', icon: AlertTriangle },
  info: { className: 'bg-sky-500/10 border-sky-500/25 text-sky-700 dark:text-sky-300', icon: Info },
  danger: { className: 'bg-red-500/10 border-red-500/25 text-red-700 dark:text-red-300', icon: XCircle },
}

// Thai copy is set in the UI sans; monospace is kept for the values people
// type or compare (domain, IP, port).
const labelClass = 'block text-[12.5px] font-medium text-[var(--text-secondary)]'
const hintClass = 'mt-1.5 mb-0 text-[12px] leading-relaxed text-[var(--text-muted)]'
const fieldClass = 'w-full dash-input h-10 font-mono text-[13.5px] tabular-nums'
const inputClass = `mt-1.5 ${fieldClass}`

export const ConnectSiteFlow: React.FC<ConnectSiteFlowProps> = ({ existingOriginId, onDone, onCancel }) => {
  const [domain, setDomain] = useState('')
  const [domainError, setDomainError] = useState('')
  const [view, setView] = useState<InspectView | null>(null)
  const [mode, setMode] = useState<ConnectionMode>('agent')
  const [address, setAddress] = useState('')
  const [port, setPort] = useState(3000)
  const [scheme, setScheme] = useState<'http' | 'https'>('http')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const { t, lang } = useT()

  const cleanDomain = normalizeDomainInput(domain)

  const applyView = (v: InspectView) => {
    setView(v)
    setMode(v.mode)
    setAddress(v.address)
    setPort(v.port)
    setScheme(v.scheme)
    setShowAdvanced(false)
  }

  const validDomain = (): boolean => {
    if (!HOSTNAME_RE.test(cleanDomain)) {
      setDomainError(t('Enter a valid domain name, e.g. shop.example.com', 'กรอกชื่อโดเมนให้ถูกรูปแบบ เช่น shop.example.com'))
      return false
    }
    // Show the hostname that will be used, e.g. after "https://…/" was pasted.
    if (domain !== cleanDomain) setDomain(cleanDomain)
    setDomainError('')
    return true
  }

  const inspectMutation = useMutation({
    mutationFn: () => onboardingApi.inspect(cleanDomain),
    onSuccess: (r: InspectResult) => applyView(describeInspect(r, lang)),
    onError: (err: any) => {
      // The probe is optional; the manual path below still works.
      toast.error(err.response?.data?.detail || t('Could not check the domain — you can set it up below', 'ตรวจโดเมนไม่สำเร็จ — ตั้งค่าเองได้ด้านล่าง'))
      applyView(describeInspect({ domain: cleanDomain, already_registered: false, reason: 'no_address' }, lang))
    },
  })

  const connectMutation = useMutation({
    mutationFn: () =>
      onboardingApi.connect({
        domain: cleanDomain,
        mode,
        port,
        ...(mode === 'direct' ? { origin_address: address.trim(), scheme } : {}),
      }),
    onSuccess: (res) => {
      toast.success(
        res.verified
          ? t('Connected — DNS already points to us', 'เชื่อมต่อแล้ว — DNS ชี้มาที่เราอยู่แล้ว')
          : t('Created — set the 1 DNS record shown on the domain card', 'สร้างแล้ว — ตั้ง DNS 1 record ตามการ์ดของโดเมน'),
      )
      const adjusted = describeOriginAdjusted(res.origin_adjusted, lang)
      if (adjusted) toast.success(adjusted, { duration: 8000 })
      onDone(res.origin_id)
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || t('Could not connect', 'เชื่อมต่อไม่สำเร็จ')),
  })

  const addDomainMutation = useMutation({
    mutationFn: () => createDomain(existingOriginId as string, { domain_name: cleanDomain }),
    onSuccess: () => {
      toast.success(t('Domain added — set the 1 DNS record shown on the domain card', 'เพิ่มโดเมนแล้ว — ตั้ง DNS 1 record ตามการ์ดของโดเมน'))
      onDone(existingOriginId as string)
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || t('Could not add the domain', 'เพิ่มโดเมนไม่สำเร็จ')),
  })

  const domainField = (
    <div>
      <label htmlFor="connect-domain" className={labelClass}>{t('Your domain', 'โดเมนของคุณ')}</label>
      <div className="relative mt-1.5">
        <Globe
          size={16}
          aria-hidden="true"
          className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]"
        />
        <input
          id="connect-domain"
          value={domain}
          onChange={(e) => {
            setDomain(e.target.value)
            if (view) setView(null)
            if (domainError) setDomainError('')
          }}
          placeholder="shop.example.com"
          className={`${fieldClass} pl-9 ${domainError ? '!border-red-500' : ''}`}
          aria-invalid={!!domainError}
          aria-describedby={domainError ? 'connect-domain-error' : 'connect-domain-hint'}
          autoFocus
          autoComplete="off"
          spellCheck={false}
        />
      </div>
      {domainError ? (
        <p id="connect-domain-error" role="alert" className="mt-1.5 mb-0 flex items-center gap-1.5 text-[12px] text-red-600 dark:text-red-400">
          <AlertCircle size={14} aria-hidden="true" className="shrink-0" />
          {domainError}
        </p>
      ) : (
        !view && (
          <p id="connect-domain-hint" className={hintClass}>
            {t('You can paste the full site link; only the domain name is used.', 'วางลิงก์ของเว็บมาทั้งลิงก์ก็ได้ ระบบจะใช้เฉพาะชื่อโดเมน')}
          </p>
        )
      )}
    </div>
  )

  // Plain divider, no bleed: the flow also renders inline on Onboarding.
  const footer = (submit: React.ReactNode) => (
    <div className="pt-4 border-t border-[var(--bg-border-subtle)] flex justify-end gap-2.5">
      {onCancel && (
        <Button variant="ghost" size="lg" type="button" onClick={onCancel}>
          {t('Cancel', 'ยกเลิก')}
        </Button>
      )}
      {submit}
    </div>
  )

  if (existingOriginId) {
    return (
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          if (validDomain()) addDomainMutation.mutate()
        }}
      >
        {domainField}
        <p className="m-0 text-[12.5px] leading-relaxed text-[var(--text-muted)]">
          {t(
            'Uses this origin’s existing connection — after adding it, set just 1 DNS record (CNAME).',
            'ใช้การเชื่อมต่อเดิมของ origin นี้ — หลังเพิ่มแล้วตั้ง DNS แค่ 1 record (CNAME)',
          )}
        </p>
        {footer(
          <Button variant="brand" size="lg" type="submit" isLoading={addDomainMutation.isPending}>
            {t('Add domain', 'เพิ่มโดเมน')}
          </Button>,
        )}
      </form>
    )
  }

  const blocked = view?.tone === 'danger'
  const canConnect =
    !!view && !blocked && port >= 1 && port <= 65535 && (mode === 'agent' || address.trim().length > 0)

  const modeOption = (value: ConnectionMode, Icon: LucideIcon, title: string, detail: string, onPick: () => void) => {
    const selected = mode === value
    const recommended = view?.mode === value
    return (
      <label
        className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-colors focus-within:ring-2 focus-within:ring-[var(--accent)] focus-within:ring-offset-1 focus-within:ring-offset-[var(--bg-surface)] ${
          selected
            ? 'border-[var(--accent)] bg-[var(--accent-subtle)]'
            : 'border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] hover:bg-[var(--nav-hover)]'
        }`}
      >
        <input
          type="radio"
          name="mode"
          checked={selected}
          onChange={onPick}
          className="mt-[9px] h-4 w-4 shrink-0 accent-[var(--accent)] dark:[color-scheme:dark] cursor-pointer focus:outline-none"
        />
        <span
          aria-hidden="true"
          className={`grid h-8 w-8 shrink-0 place-items-center rounded-md border ${
            selected
              ? 'border-[var(--accent-border)] bg-[var(--bg-surface)] text-[var(--accent)]'
              : 'border-[var(--bg-border)] bg-[var(--bg-primary)] text-[var(--text-muted)]'
          }`}
        >
          <Icon size={16} />
        </span>
        <span className="min-w-0">
          <span className="flex flex-wrap items-center gap-2 text-[13.5px] font-semibold text-[var(--text-primary)]">
            {title}
            {recommended && (
              <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-px text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
                {t('Recommended', 'แนะนำ')}
              </span>
            )}
          </span>
          <span className="mt-0.5 block text-[12.5px] leading-relaxed text-[var(--text-muted)]">{detail}</span>
        </span>
      </label>
    )
  }

  const tone = view ? TONE[view.tone] : null

  return (
    <div className="space-y-5">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          if (validDomain()) inspectMutation.mutate()
        }}
      >
        {domainField}
        {!view && (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 pt-1">
            <Button variant="brand" size="lg" type="submit" isLoading={inspectMutation.isPending} icon={<Search size={15} />}>
              {t('Check domain', 'ตรวจสอบโดเมน')}
            </Button>
            <button
              type="button"
              className="text-[12.5px] text-[var(--text-secondary)] hover:text-[var(--accent)] underline decoration-[var(--bg-border-hover)] underline-offset-4 hover:decoration-current cursor-pointer rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
              onClick={() => {
                if (validDomain()) applyView(describeInspect({ domain: cleanDomain, already_registered: false, reason: 'no_address' }, lang))
              }}
            >
              {t('Skip the check, set up manually', 'ข้ามการตรวจ ตั้งค่าเอง')}
            </button>
          </div>
        )}
      </form>

      {view && tone && (
        <form
          className="space-y-5"
          onSubmit={(e) => {
            e.preventDefault()
            if (canConnect) connectMutation.mutate()
          }}
        >
          <div role="status" className={`flex items-start gap-2.5 p-3.5 rounded-lg border text-[13px] leading-relaxed ${tone.className}`}>
            <tone.icon size={17} aria-hidden="true" className="mt-px shrink-0" />
            <span>{view.message}</span>
          </div>

          {!blocked && (
            <fieldset className="space-y-2 m-0 p-0 border-0">
              <legend className={`${labelClass} mb-2`}>{t('How to connect', 'วิธีเชื่อมต่อ')}</legend>
              {modeOption(
                'direct',
                Server,
                t('Connect directly to the server', 'ต่อตรงไปที่เซิร์ฟเวอร์'),
                t('The server has a public IP — nothing to install', 'เซิร์ฟเวอร์มี public IP — ไม่ต้องติดตั้งอะไร'),
                () => {
                setMode('direct')
                // Detected values when there are some, else the common HTTPS default.
                setPort(view.mode === 'direct' ? view.port : 443)
                setScheme(view.mode === 'direct' ? view.scheme : 'https')
                },
              )}
              {modeOption(
                'agent',
                Terminal,
                t('Use the Agent', 'ใช้ Agent'),
                t('The machine is behind NAT/firewall — no inbound port needed', 'เครื่องอยู่หลัง NAT/firewall — ไม่ต้องเปิดพอร์ตขาเข้า'),
                () => {
                setMode('agent')
                setPort(3000)
                },
              )}
            </fieldset>
          )}

          {!blocked && mode === 'agent' && (
            <div className="max-w-[200px]">
              <label htmlFor="connect-port" className={labelClass}>{t('The site runs on port', 'เว็บรันที่ port')}</label>
              <input
                id="connect-port"
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(e) => setPort(parseInt(e.target.value, 10) || 0)}
                className={inputClass}
              />
            </div>
          )}

          {!blocked && mode === 'direct' && (
            view.mode === 'direct' && !showAdvanced ? (
              <div className="flex items-center justify-between gap-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] px-3.5 py-2.5">
                <div className="min-w-0">
                  <span className="block text-[12px] text-[var(--text-muted)]">{t('Send traffic to', 'ส่ง traffic ไปที่')}</span>
                  <span className="block truncate font-mono text-[13.5px] text-[var(--text-primary)]">
                    {scheme}://{address}:{port}
                  </span>
                </div>
                <Button variant="secondary" size="sm" type="button" onClick={() => setShowAdvanced(true)} icon={<Pencil size={13} />}>
                  {t('Edit', 'แก้ไข')}
                </Button>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-[7rem_1fr_6rem]">
                  <div>
                    <label htmlFor="connect-scheme" className={labelClass}>Protocol</label>
                    <select id="connect-scheme" value={scheme} onChange={(e) => setScheme(e.target.value as 'http' | 'https')} className={inputClass}>
                      <option value="https">https</option>
                      <option value="http">http</option>
                    </select>
                  </div>
                  <div className="col-span-2 row-start-2 sm:col-span-1 sm:row-start-auto">
                    <label htmlFor="connect-address" className={labelClass}>{t('Server IP', 'IP ของเซิร์ฟเวอร์')}</label>
                    <input id="connect-address" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="203.0.113.10" className={inputClass} />
                  </div>
                  <div>
                    <label htmlFor="connect-direct-port" className={labelClass}>Port</label>
                    <input id="connect-direct-port" type="number" min={1} max={65535} value={port} onChange={(e) => setPort(parseInt(e.target.value, 10) || 0)} className={inputClass} />
                  </div>
                </div>
                {view.mode === 'direct' && (
                  <button
                    type="button"
                    onClick={() => setShowAdvanced(false)}
                    className="text-[12.5px] text-[var(--text-secondary)] hover:text-[var(--accent)] cursor-pointer rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
                  >
                    {t('Hide', 'ซ่อน')}
                  </button>
                )}
              </div>
            )
          )}

          {footer(
            <Button variant="brand" size="lg" type="submit" disabled={!canConnect} isLoading={connectMutation.isPending}>
              {t('Connect', 'เชื่อมต่อ')} <ArrowRight size={15} aria-hidden="true" />
            </Button>,
          )}
        </form>
      )}
    </div>
  )
}

export default ConnectSiteFlow
