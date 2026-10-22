import React from 'react'

// Renders the short report text the AI endpoints return (prompt rules in
// services/gemini_service.py REPORT_STYLE): "- " items, a line that is only
// **bold** as a section label, and inline **bold** / `code`. Nothing else is
// interpreted, so stray markdown shows as plain text instead of HTML.

const inline = (text: string) =>
  text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return (
        <strong key={i} className="font-semibold text-[var(--text-primary)]">
          {part.slice(2, -2)}
        </strong>
      )
    }
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code key={i} className="rounded bg-[var(--bg-surface-elevated)] px-1 py-px font-mono text-[0.92em] text-[var(--text-primary)] break-all">
          {part.slice(1, -1)}
        </code>
      )
    }
    return part
  })

export const ReportText: React.FC<{ text: string; className?: string }> = ({ text, className = '' }) => {
  const blocks: React.ReactNode[] = []
  let items: string[] = []
  const flush = () => {
    if (!items.length) return
    blocks.push(
      <ul key={`ul-${blocks.length}`} className="m-0 pl-4 list-disc marker:text-[var(--text-muted)] space-y-1">
        {items.map((t, i) => (
          <li key={i}>{inline(t)}</li>
        ))}
      </ul>,
    )
    items = []
  }

  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line) {
      flush()
      continue
    }
    const item = line.match(/^(?:[-*•]|\d+\.)\s+(.*)$/)
    if (item) {
      items.push(item[1])
      continue
    }
    flush()
    const label = line.match(/^(?:#{1,4}\s*)?\*\*([^*]+)\*\*:?$/) || line.match(/^#{1,4}\s+(.*)$/)
    blocks.push(
      label ? (
        <p key={blocks.length} className="m-0 pt-1 text-[0.95em] font-semibold text-[var(--text-primary)]">
          {label[1]}
        </p>
      ) : (
        <p key={blocks.length} className="m-0">
          {inline(line)}
        </p>
      ),
    )
  }
  flush()

  return <div className={`space-y-1.5 leading-relaxed text-[var(--text-secondary)] ${className}`}>{blocks}</div>
}

export default ReportText
