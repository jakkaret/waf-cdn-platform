import React, { useState } from 'react'
import { toast } from 'react-hot-toast'
import { DnsInstructions as DnsInstructionsType } from '../types'
import { Copy, Check } from 'lucide-react'

interface DnsInstructionsProps {
  instructions: DnsInstructionsType
}

const CopyButton: React.FC<{ text: string }> = ({ text }) => {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      toast.success('Copied DNS record to clipboard')
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast.error('Failed to copy')
    }
  }

  return (
    <button
      onClick={handleCopy}
      title="Copy to clipboard"
      className="shrink-0 p-1.5 rounded-md bg-[var(--bg-surface)] text-[var(--text-muted)] hover:text-orange-500 hover:bg-orange-500/10 transition-colors border border-[var(--bg-border)] cursor-pointer"
    >
      {copied ? <Check size={13} className="text-emerald-500" /> : <Copy size={13} />}
    </button>
  )
}

interface DnsRowProps {
  type: string
  name: string
  value: string
  typeColor?: string
}

const DnsRow: React.FC<DnsRowProps> = ({ type, name, value, typeColor = '#38bdf8' }) => (
  <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] overflow-hidden font-mono text-[12px]">
    <div className="px-3 py-1.5 bg-[var(--bg-surface-elevated)] border-b border-[var(--bg-border)] flex items-center gap-2">
      <span
        className="text-[10.5px] font-bold px-2 py-0.5 rounded font-mono"
        style={{ background: `${typeColor}20`, color: typeColor }}
      >
        {type}
      </span>
      <span className="text-[11px] text-[var(--text-muted)]">DNS Record Entry</span>
    </div>
    <div className="p-3 space-y-2.5">
      <div>
        <p className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider mb-1 font-bold">
          Host / Record Name
        </p>
        <div className="flex items-center gap-2">
          <code className="flex-1 text-[11.5px] text-[var(--text-primary)] font-mono bg-[var(--bg-surface)] px-2.5 py-1.5 rounded border border-[var(--bg-border)] break-all">
            {name}
          </code>
          <CopyButton text={name} />
        </div>
      </div>
      <div>
        <p className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider mb-1 font-bold">
          Value / Target Route
        </p>
        <div className="flex items-center gap-2">
          <code className="flex-1 text-[11.5px] text-orange-500 font-mono bg-[var(--bg-surface)] px-2.5 py-1.5 rounded border border-[var(--bg-border)] break-all font-bold">
            {value}
          </code>
          <CopyButton text={value} />
        </div>
      </div>
    </div>
  </div>
)

export const DnsInstructions: React.FC<DnsInstructionsProps> = ({ instructions }) => {
  return (
    <div className="space-y-3">
      <div>
        <p className="text-[11px] font-bold text-[var(--text-muted)] uppercase font-mono tracking-wider mb-1.5">
          Record 1 — CNAME (Traffic Ingestion)
        </p>
        <DnsRow
          type="CNAME"
          name={instructions.cname_record.name}
          value={instructions.cname_record.value}
          typeColor="#38bdf8"
        />
      </div>
      <div>
        <p className="text-[11px] font-bold text-[var(--text-muted)] uppercase font-mono tracking-wider mb-1.5">
          Record 2 — TXT (Ownership Verification)
        </p>
        <DnsRow
          type="TXT"
          name={instructions.txt_record.name}
          value={instructions.txt_record.value}
          typeColor="#f59e0b"
        />
      </div>
    </div>
  )
}
