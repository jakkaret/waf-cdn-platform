import React, { useState } from 'react'
import { toast } from 'react-hot-toast'
import { DnsInstructions } from './DnsInstructions'
import { Button } from './ui/Button'
import { Modal } from './ui/Modal'
import { createDomain, verifyDomain } from '../api/domains'
import { Domain, DnsInstructions as DnsInstructionsType } from '../types'
import { Check, Globe, RefreshCw, AlertCircle, ShieldCheck } from 'lucide-react'

interface DomainSetupWizardProps {
  open: boolean
  onClose: () => void
  onSuccess: () => void
  originId: string
}

type WizardStep = 'enter_domain' | 'dns_instructions' | 'verify_dns' | 'done' | 'failed'

export const DomainSetupWizard: React.FC<DomainSetupWizardProps> = ({
  open,
  onClose,
  onSuccess,
  originId,
}) => {
  const [step, setStep] = useState<WizardStep>('enter_domain')
  const [domainName, setDomainName] = useState('')
  const [domainNameError, setDomainNameError] = useState('')
  const [createdDomain, setCreatedDomain] = useState<Domain | null>(null)
  const [dnsInstructions, setDnsInstructions] = useState<DnsInstructionsType | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [verifyError, setVerifyError] = useState('')

  const validateDomain = (value: string) => {
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
    if (!value.trim()) return 'Domain name is required'
    if (!domainRegex.test(value)) return 'Please enter a valid domain name (e.g. example.com or app.example.com)'
    return ''
  }

  const handleCreateDomain = async (e: React.FormEvent) => {
    e.preventDefault()
    const error = validateDomain(domainName)
    if (error) {
      setDomainNameError(error)
      return
    }

    setIsLoading(true)
    try {
      const res = await createDomain(originId, { domain_name: domainName })
      setCreatedDomain(res.data.domain)
      setDnsInstructions(res.data.dns_instructions)
      setStep('dns_instructions')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to add domain')
    } finally {
      setIsLoading(false)
    }
  }

  const handleVerifyDns = async () => {
    if (!createdDomain) return
    setIsLoading(true)
    setVerifyError('')
    try {
      const res = await verifyDomain(originId, createdDomain.domain_id)
      if (res.data.status === 'verified') {
        setStep('done')
        toast.success('Domain verified successfully!')
      } else {
        setVerifyError(res.data.message || 'DNS records not found yet. Please wait a few minutes for propagation.')
      }
    } catch (err: any) {
      setVerifyError(err.response?.data?.detail || 'Verification failed. Check your DNS records and try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const handleClose = () => {
    setStep('enter_domain')
    setDomainName('')
    setDomainNameError('')
    setCreatedDomain(null)
    setDnsInstructions(null)
    setVerifyError('')
    onClose()
  }

  const handleDone = () => {
    onSuccess()
    handleClose()
  }

  const STEPS = ['Domain', 'DNS Setup', 'Verify', 'Done']
  const stepIndex = {
    enter_domain: 0,
    dns_instructions: 1,
    verify_dns: 2,
    done: 3,
    failed: 2,
  }[step]

  const titleMap: Record<WizardStep, string> = {
    enter_domain: 'Connect Custom Domain',
    dns_instructions: 'Configure DNS Records',
    verify_dns: 'Verify DNS Propagation',
    done: 'Domain Provisioned Successfully',
    failed: 'Verification Incomplete',
  }

  return (
    <Modal open={open} onClose={handleClose} title={titleMap[step]}>
      {/* Stepper */}
      <div className="flex items-center mb-6 font-mono text-[11px]">
        {STEPS.map((label, index) => (
          <React.Fragment key={label}>
            <div className="flex flex-col items-center flex-1">
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-[10.5px] font-bold border transition-all ${
                  index < stepIndex
                    ? 'bg-emerald-500 border-emerald-500 text-white'
                    : index === stepIndex
                    ? 'bg-orange-500 border-orange-500 text-white shadow-sm'
                    : 'bg-[var(--bg-primary)] border-[var(--bg-border)] text-[var(--text-muted)]'
                }`}
              >
                {index < stepIndex ? <Check size={12} strokeWidth={3} /> : index + 1}
              </div>
              <span
                className={`mt-1 font-semibold ${
                  index === stepIndex
                    ? 'text-orange-500'
                    : index < stepIndex
                    ? 'text-emerald-500'
                    : 'text-[var(--text-muted)]'
                }`}
              >
                {label}
              </span>
            </div>
            {index < STEPS.length - 1 && (
              <div
                className={`h-0.5 flex-1 -mt-4 transition-all ${
                  index < stepIndex ? 'bg-emerald-500' : 'bg-[var(--bg-border)]'
                }`}
              />
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Step 1: Enter Domain */}
      {step === 'enter_domain' && (
        <form onSubmit={handleCreateDomain} className="space-y-4 text-[12.5px]">
          <div>
            <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
              Target Hostname / FQDN
            </label>
            <input
              type="text"
              value={domainName}
              onChange={(e) => {
                setDomainName(e.target.value)
                if (domainNameError) setDomainNameError('')
              }}
              className="w-full dash-input font-mono"
              placeholder="e.g. secure.example.com or company.org"
              autoFocus
            />
            {domainNameError && <p className="mt-1 text-[11px] font-mono text-red-500">{domainNameError}</p>}
            <p className="mt-2 text-[11.5px] text-[var(--text-muted)] font-mono">
              You will be provided with CNAME and TXT records to point at your DNS registrar.
            </p>
          </div>
          <div className="pt-2 border-t border-[var(--bg-border)] flex justify-end gap-2.5">
            <Button variant="ghost" type="button" onClick={handleClose}>
              Cancel
            </Button>
            <Button variant="brand" type="submit" isLoading={isLoading}>
              Generate DNS Keys
            </Button>
          </div>
        </form>
      )}

      {/* Step 2: DNS Instructions */}
      {step === 'dns_instructions' && dnsInstructions && (
        <div className="space-y-4 text-[12.5px]">
          <p className="text-[12px] text-[var(--text-secondary)] m-0">
            Publish these DNS entries at your DNS host for{' '}
            <strong className="text-orange-500 font-mono">{domainName}</strong>:
          </p>
          <DnsInstructions instructions={dnsInstructions} />
          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-[11.5px] text-amber-500 font-mono">
            DNS propagation typically takes 1–5 minutes.
          </div>
          <div className="pt-2 border-t border-[var(--bg-border)] flex justify-end gap-2.5">
            <Button variant="ghost" type="button" onClick={handleClose}>
              Configure Later
            </Button>
            <Button variant="brand" onClick={() => setStep('verify_dns')}>
              I&apos;ve Added the Records →
            </Button>
          </div>
        </div>
      )}

      {/* Step 3: Verify DNS */}
      {step === 'verify_dns' && (
        <div className="space-y-4 text-[12.5px]">
          <p className="text-[12px] text-[var(--text-secondary)] m-0">
            Querying DNS root servers for <strong className="text-orange-500 font-mono">{domainName}</strong>...
          </p>

          <div className="p-4 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] space-y-3 font-mono">
            <div className="flex items-center gap-3">
              <Globe size={18} className="text-sky-500" />
              <div>
                <p className="font-bold text-[12.5px] text-[var(--text-primary)] m-0">DNS Record Lookup</p>
                <p className="text-[11px] text-[var(--text-muted)] m-0">Checking CNAME and TXT verification</p>
              </div>
            </div>

            {verifyError && (
              <div className="p-3 rounded bg-red-500/10 border border-red-500/20 text-[11.5px] text-red-400">
                {verifyError}
              </div>
            )}
          </div>

          <div className="pt-2 border-t border-[var(--bg-border)] flex justify-end gap-2.5">
            <Button variant="ghost" type="button" onClick={() => setStep('dns_instructions')}>
              ← Back to Records
            </Button>
            <Button variant="brand" onClick={handleVerifyDns} isLoading={isLoading}>
              {isLoading ? 'Checking DNS...' : 'Verify DNS Now'}
            </Button>
          </div>
        </div>
      )}

      {/* Step 4: Done */}
      {step === 'done' && (
        <div className="text-center space-y-4 py-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center mx-auto text-emerald-500">
            <ShieldCheck size={26} />
          </div>
          <div>
            <h3 className="text-[16px] font-bold text-[var(--text-primary)] font-mono m-0">
              Domain Verified & Secured
            </h3>
            <p className="text-[12px] text-[var(--text-secondary)] font-mono mt-1">
              <strong className="text-orange-500">{domainName}</strong> is now routing through CloudWAF.
            </p>
          </div>
          <p className="text-[11.5px] text-[var(--text-muted)] font-mono">
            Automated SSL / TLS certificates will be issued via Let&apos;s Encrypt / ZeroSSL.
          </p>
          <div className="pt-2">
            <Button variant="brand" onClick={handleDone} className="w-full">
              Complete Setup
            </Button>
          </div>
        </div>
      )}
    </Modal>
  )
}
