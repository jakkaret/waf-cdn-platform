import React from 'react'
import { useSearchParams } from 'react-router-dom'
import { TopBar } from '../components/layout/TopBar'
import MLRules from './MLRules'
import ThresholdProposals from './ThresholdProposals'
import { useT } from '../i18n'

// One review queue for everything that changes how the WAF blocks (UX
// reorganization 2026-10-28): rules the ML model proposed and anomaly
// threshold tuning. The two keep their own workflows and backends -- an ML
// rule is approved by the origin's Owner or Editor, a threshold proposal by
// its Owner -- so this page only puts them side by side behind a type filter.
// ?type=ml|tuning keeps the old /ml-rules and /threshold-proposals links
// landing on the right list.

export type ProposalType = 'ml' | 'tuning'

const TYPES: { id: ProposalType; label: string; hint: string; labelTh: string; hintTh: string }[] = [
  {
    id: 'ml',
    label: 'ML anomaly rules',
    hint: 'Block rules proposed from detected requests',
    labelTh: 'กฎ ML anomaly',
    hintTh: 'กฎบล็อกที่เสนอจาก request ที่ตรวจพบ',
  },
  {
    id: 'tuning',
    label: 'Threshold tuning',
    hint: 'Changes to an origin’s anomaly score threshold',
    labelTh: 'ปรับค่า threshold',
    hintTh: 'การเปลี่ยนเกณฑ์คะแนน anomaly ของ origin',
  },
]

export const proposalTypeFrom = (value: string | null): ProposalType => (value === 'tuning' ? 'tuning' : 'ml')

export const RuleProposals: React.FC = () => {
  const [params, setParams] = useSearchParams()
  const type = proposalTypeFrom(params.get('type'))
  const { t } = useT()

  const select = (next: ProposalType) => {
    const p = new URLSearchParams(params)
    p.set('type', next)
    setParams(p, { replace: true })
  }

  return (
    <div className="animate-fade-in pb-12">
      <TopBar
        title={t('Rule proposals', 'กฎที่รอตรวจ')}
        subtitle={t(
          'Changes the system suggests for your origins. Nothing here affects traffic until someone with the right role approves it.',
          'การเปลี่ยนแปลงที่ระบบเสนอสำหรับ origin ของคุณ จะยังไม่มีผลกับทราฟฟิกจนกว่าผู้มีสิทธิ์จะอนุมัติ',
        )}
      />

      <div role="tablist" aria-label={t('Proposal type', 'ประเภทข้อเสนอ')} className="mb-5 flex flex-wrap gap-2">
        {TYPES.map((item) => {
          const active = item.id === type
          return (
            <button
              key={item.id}
              type="button"
              role="tab"
              id={`proposal-tab-${item.id}`}
              aria-selected={active}
              aria-controls={`proposal-panel-${item.id}`}
              onClick={() => select(item.id)}
              className={`min-w-[200px] text-left rounded-lg border px-3.5 py-2.5 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
                active
                  ? 'border-[var(--accent)] bg-[var(--nav-active)]'
                  : 'border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)]'
              }`}
            >
              <span className={`block text-[13.5px] ${active ? 'font-semibold text-[var(--text-primary)]' : 'font-medium text-[var(--text-secondary)]'}`}>
                {t(item.label, item.labelTh)}
              </span>
              <span className="block text-[12px] text-[var(--text-muted)]">{t(item.hint, item.hintTh)}</span>
            </button>
          )
        })}
      </div>

      <div role="tabpanel" id={`proposal-panel-${type}`} aria-labelledby={`proposal-tab-${type}`}>
        {type === 'ml' ? <MLRules embedded /> : <ThresholdProposals embedded />}
      </div>
    </div>
  )
}

export default RuleProposals
