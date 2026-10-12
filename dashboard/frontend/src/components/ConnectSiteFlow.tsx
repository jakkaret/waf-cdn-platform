import React, { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Globe, Search, ArrowRight, Server, Terminal, ChevronDown, ChevronRight } from 'lucide-react'
import { Button } from './ui/Button'
import { onboardingApi, ConnectionMode, InspectResult } from '../api/onboarding'
import { createDomain } from '../api/domains'
import { describeInspect, normalizeDomainInput, InspectView } from '../lib/connectProgress'

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

const TONE_CLASS: Record<InspectView['tone'], string> = {
  success: 'bg-emerald-500/10 border-emerald-500/25 text-emerald-600 dark:text-emerald-400',
  warning: 'bg-amber-500/10 border-amber-500/25 text-amber-600 dark:text-amber-400',
  info: 'bg-sky-500/10 border-sky-500/25 text-sky-600 dark:text-sky-400',
  danger: 'bg-red-500/10 border-red-500/25 text-red-600 dark:text-red-400',
}

const inputClass = 'mt-1 w-full dash-input font-mono text-[13px]'
const labelClass = 'block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)]'

export const ConnectSiteFlow: React.FC<ConnectSiteFlowProps> = ({ existingOriginId, onDone, onCancel }) => {
  const [domain, setDomain] = useState('')
  const [domainError, setDomainError] = useState('')
  const [view, setView] = useState<InspectView | null>(null)
  const [mode, setMode] = useState<ConnectionMode>('agent')
  const [address, setAddress] = useState('')
  const [port, setPort] = useState(3000)
  const [scheme, setScheme] = useState<'http' | 'https'>('http')
  const [showAdvanced, setShowAdvanced] = useState(false)

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
      setDomainError('กรอกชื่อโดเมนให้ถูกรูปแบบ เช่น shop.example.com')
      return false
    }
    // Show the hostname that will be used, e.g. after "https://…/" was pasted.
    if (domain !== cleanDomain) setDomain(cleanDomain)
    setDomainError('')
    return true
  }

  const inspectMutation = useMutation({
    mutationFn: () => onboardingApi.inspect(cleanDomain),
    onSuccess: (r: InspectResult) => applyView(describeInspect(r)),
    onError: (err: any) => {
      // The probe is optional; the manual path below still works.
      toast.error(err.response?.data?.detail || 'ตรวจโดเมนไม่สำเร็จ — ตั้งค่าเองได้ด้านล่าง')
      applyView(describeInspect({ domain: cleanDomain, already_registered: false, reason: 'no_address' }))
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
      toast.success(res.verified ? 'เชื่อมต่อแล้ว — DNS ชี้มาที่เราอยู่แล้ว' : 'สร้างแล้ว — ตั้ง DNS 1 record ตามการ์ดของโดเมน')
      onDone(res.origin_id)
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'เชื่อมต่อไม่สำเร็จ'),
  })

  const addDomainMutation = useMutation({
    mutationFn: () => createDomain(existingOriginId as string, { domain_name: cleanDomain }),
    onSuccess: () => {
      toast.success('เพิ่มโดเมนแล้ว — ตั้ง DNS 1 record ตามการ์ดของโดเมน')
      onDone(existingOriginId as string)
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'เพิ่มโดเมนไม่สำเร็จ'),
  })

  const domainField = (
    <div>
      <label htmlFor="connect-domain" className={labelClass}>โดเมนของคุณ</label>
      <input
        id="connect-domain"
        value={domain}
        onChange={(e) => {
          setDomain(e.target.value)
          if (view) setView(null)
          if (domainError) setDomainError('')
        }}
        placeholder="shop.example.com"
        className={inputClass}
        autoFocus
        autoComplete="off"
        spellCheck={false}
      />
      {domainError && <p className="mt-1 text-[11px] font-mono text-red-500 m-0">{domainError}</p>}
    </div>
  )

  if (existingOriginId) {
    return (
      <form
        className="space-y-4 text-[12.5px]"
        onSubmit={(e) => {
          e.preventDefault()
          if (validDomain()) addDomainMutation.mutate()
        }}
      >
        {domainField}
        <p className="text-[11.5px] text-[var(--text-muted)] font-mono m-0">
          ใช้การเชื่อมต่อเดิมของ origin นี้ — หลังเพิ่มแล้วตั้ง DNS แค่ 1 record (CNAME)
        </p>
        <div className="pt-2 border-t border-[var(--bg-border)] flex justify-end gap-2.5">
          {onCancel && <Button variant="ghost" type="button" onClick={onCancel}>ยกเลิก</Button>}
          <Button variant="brand" type="submit" isLoading={addDomainMutation.isPending}>เพิ่มโดเมน</Button>
        </div>
      </form>
    )
  }

  const blocked = view?.tone === 'danger'
  const canConnect =
    !!view && !blocked && port >= 1 && port <= 65535 && (mode === 'agent' || address.trim().length > 0)

  return (
    <div className="space-y-4 text-[12.5px]">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          if (validDomain()) inspectMutation.mutate()
        }}
      >
        {domainField}
        {!view && (
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="brand" type="submit" isLoading={inspectMutation.isPending} icon={<Search size={14} />}>
              ตรวจสอบโดเมน
            </Button>
            <button
              type="button"
              className="text-[11.5px] font-mono text-[var(--text-muted)] hover:text-orange-500 underline underline-offset-2 cursor-pointer"
              onClick={() => {
                if (validDomain()) applyView(describeInspect({ domain: cleanDomain, already_registered: false, reason: 'no_address' }))
              }}
            >
              ข้ามการตรวจ ตั้งค่าเอง
            </button>
          </div>
        )}
      </form>

      {view && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (canConnect) connectMutation.mutate()
          }}
        >
          <div className={`p-3 rounded-lg border font-mono text-[11.5px] ${TONE_CLASS[view.tone]}`}>
            <Globe size={13} className="inline -mt-0.5 mr-1.5" />
            {view.message}
          </div>

          {!blocked && (
            <fieldset className="space-y-2">
              <legend className={labelClass}>วิธีเชื่อมต่อ</legend>
              <label className={`flex items-start gap-2.5 p-3 rounded-lg border cursor-pointer ${mode === 'direct' ? 'border-orange-500 bg-orange-500/5' : 'border-[var(--bg-border)]'}`}>
                <input
                  type="radio"
                  name="mode"
                  checked={mode === 'direct'}
                  onChange={() => {
                    setMode('direct')
                    // Detected values when there are some, else the common HTTPS default.
                    setPort(view.mode === 'direct' ? view.port : 443)
                    setScheme(view.mode === 'direct' ? view.scheme : 'https')
                  }}
                  className="mt-0.5"
                />
                <span>
                  <span className="font-mono font-bold text-[12.5px] flex items-center gap-1.5"><Server size={13} /> ต่อตรงไปที่เซิร์ฟเวอร์</span>
                  <span className="block text-[11px] text-[var(--text-muted)] font-mono">เซิร์ฟเวอร์มี public IP — ไม่ต้องติดตั้งอะไร</span>
                </span>
              </label>
              <label className={`flex items-start gap-2.5 p-3 rounded-lg border cursor-pointer ${mode === 'agent' ? 'border-orange-500 bg-orange-500/5' : 'border-[var(--bg-border)]'}`}>
                <input
                  type="radio"
                  name="mode"
                  checked={mode === 'agent'}
                  onChange={() => {
                    setMode('agent')
                    setPort(3000)
                  }}
                  className="mt-0.5"
                />
                <span>
                  <span className="font-mono font-bold text-[12.5px] flex items-center gap-1.5"><Terminal size={13} /> ใช้ Agent</span>
                  <span className="block text-[11px] text-[var(--text-muted)] font-mono">เครื่องอยู่หลัง NAT/firewall — ไม่ต้องเปิดพอร์ตขาเข้า</span>
                </span>
              </label>
            </fieldset>
          )}

          {!blocked && mode === 'agent' && (
            <div className="max-w-[180px]">
              <label htmlFor="connect-port" className={labelClass}>เว็บรันที่ port</label>
              <input
                id="connect-port"
                type="number"
                value={port}
                onChange={(e) => setPort(parseInt(e.target.value, 10) || 0)}
                className={inputClass}
              />
            </div>
          )}

          {!blocked && mode === 'direct' && (
            <div className="space-y-2">
              {view.mode === 'direct' && !showAdvanced ? (
                <button
                  type="button"
                  onClick={() => setShowAdvanced(true)}
                  className="flex items-center gap-1 text-[11.5px] font-mono text-[var(--text-muted)] hover:text-orange-500 cursor-pointer"
                >
                  <ChevronRight size={13} /> {scheme}://{address}:{port} — แก้ไข
                </button>
              ) : (
                <>
                  {view.mode === 'direct' && (
                    <button type="button" onClick={() => setShowAdvanced(false)} className="flex items-center gap-1 text-[11.5px] font-mono text-[var(--text-muted)] cursor-pointer">
                      <ChevronDown size={13} /> ซ่อน
                    </button>
                  )}
                  <div className="grid grid-cols-6 gap-2">
                    <div className="col-span-2">
                      <label htmlFor="connect-scheme" className={labelClass}>Protocol</label>
                      <select id="connect-scheme" value={scheme} onChange={(e) => setScheme(e.target.value as 'http' | 'https')} className={inputClass}>
                        <option value="https">https</option>
                        <option value="http">http</option>
                      </select>
                    </div>
                    <div className="col-span-3">
                      <label htmlFor="connect-address" className={labelClass}>IP ของเซิร์ฟเวอร์</label>
                      <input id="connect-address" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="203.0.113.10" className={inputClass} />
                    </div>
                    <div className="col-span-1">
                      <label htmlFor="connect-direct-port" className={labelClass}>Port</label>
                      <input id="connect-direct-port" type="number" value={port} onChange={(e) => setPort(parseInt(e.target.value, 10) || 0)} className={inputClass} />
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          <div className="pt-2 border-t border-[var(--bg-border)] flex justify-end gap-2.5">
            {onCancel && <Button variant="ghost" type="button" onClick={onCancel}>ยกเลิก</Button>}
            <Button variant="brand" type="submit" disabled={!canConnect} isLoading={connectMutation.isPending}>
              เชื่อมต่อ <ArrowRight size={14} />
            </Button>
          </div>
        </form>
      )}
    </div>
  )
}

export default ConnectSiteFlow
