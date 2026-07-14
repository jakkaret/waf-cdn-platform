import React, { useState } from 'react';
import { toast } from 'react-hot-toast';
import { DnsInstructions as DnsInstructionsType } from '../types';

interface DnsInstructionsProps {
  instructions: DnsInstructionsType;
}

const CopyButton: React.FC<{ text: string }> = ({ text }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast.success('Copied to clipboard!');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error('Failed to copy');
    }
  };

  return (
    <button
      onClick={handleCopy}
      title="Copy to clipboard"
      className="flex-shrink-0 p-1.5 rounded-md bg-bg-surface text-text-muted hover:text-accent hover:bg-accent/10 transition-colors border border-bg-border"
    >
      {copied ? (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#68d391" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ) : (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </svg>
      )}
    </button>
  );
};

interface DnsRowProps {
  type: string;
  name: string;
  value: string;
  typeColor?: string;
}

const DnsRow: React.FC<DnsRowProps> = ({ type, name, value, typeColor = '#667eea' }) => (
  <div className="rounded-lg border border-bg-border bg-bg-surface2 overflow-hidden">
    <div className="px-3 py-1.5 bg-bg-surface border-b border-bg-border flex items-center gap-2">
      <span
        className="text-[10px] font-bold px-2 py-0.5 rounded font-mono"
        style={{ background: `${typeColor}20`, color: typeColor }}
      >
        {type}
      </span>
      <span className="text-xs text-text-muted">Record</span>
    </div>
    <div className="p-3 space-y-2">
      <div>
        <p className="text-[10px] text-text-muted uppercase tracking-wider mb-0.5">Name / Host</p>
        <div className="flex items-center gap-2">
          <code className="flex-1 text-xs text-text-primary font-mono bg-[#0d1117] px-2 py-1.5 rounded border border-bg-border break-all">
            {name}
          </code>
          <CopyButton text={name} />
        </div>
      </div>
      <div>
        <p className="text-[10px] text-text-muted uppercase tracking-wider mb-0.5">Value / Points To</p>
        <div className="flex items-center gap-2">
          <code className="flex-1 text-xs text-text-primary font-mono bg-[#0d1117] px-2 py-1.5 rounded border border-bg-border break-all">
            {value}
          </code>
          <CopyButton text={value} />
        </div>
      </div>
    </div>
  </div>
);

export const DnsInstructions: React.FC<DnsInstructionsProps> = ({ instructions }) => {
  return (
    <div className="space-y-3">
      <div>
        <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
          Record 1 — CNAME (Traffic Routing)
        </p>
        <DnsRow
          type="CNAME"
          name={instructions.cname_record.name}
          value={instructions.cname_record.value}
          typeColor="#667eea"
        />
      </div>
      <div>
        <p className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
          Record 2 — TXT (Domain Verification)
        </p>
        <DnsRow
          type="TXT"
          name={instructions.txt_record.name}
          value={instructions.txt_record.value}
          typeColor="#f6ad55"
        />
      </div>
    </div>
  );
};
