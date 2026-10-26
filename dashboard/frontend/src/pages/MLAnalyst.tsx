import React from 'react'
import { useSearchParams } from 'react-router-dom'
import { TopBar } from '../components/layout/TopBar'
import { MLInsights } from '../components/ml/MLInsights'
import { ManualAnalyzer } from '../components/ml/ManualAnalyzer'

// AI Security Analyst. Opens on ML Insights: Gen 3 scores of the origin's real
// traffic, nothing to type in. Scoring one request by hand (and proposing a
// rule from it) is the second tab, ?tab=analyze.

const TABS = [
  { id: 'insights', label: 'ML Insights' },
  { id: 'analyze', label: 'วิเคราะห์ request เอง' },
] as const

type TabId = (typeof TABS)[number]['id']

export const MLAnalyst: React.FC = () => {
  const [params, setParams] = useSearchParams()
  const tab: TabId = params.get('tab') === 'analyze' ? 'analyze' : 'insights'
  const select = (id: TabId) => setParams(id === 'insights' ? {} : { tab: id }, { replace: true })

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title="AI Security Analyst"
        subtitle={
          tab === 'insights'
            ? 'ML Insights: คะแนนจากโมเดล Gen 3 ของ traffic จริงทุก request ใช้วิเคราะห์เท่านั้น ไม่บล็อก traffic'
            : 'ทดสอบ HTTP request กับโมเดล Gen 3 ผลใช้วิเคราะห์เท่านั้น ไม่บล็อก traffic จริง'
        }
      />

      <div role="tablist" aria-label="AI Security Analyst" className="flex gap-1 border-b border-[var(--bg-border)]">
        {TABS.map((t) => (
          <button
            key={t.id}
            id={`analyst-tab-${t.id}`}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            aria-controls={`analyst-panel-${t.id}`}
            onClick={() => select(t.id)}
            className={`-mb-px h-9 px-3 border-b-2 text-[13px] font-medium transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] rounded-t ${
              tab === t.id
                ? 'border-[var(--accent)] text-[var(--text-primary)]'
                : 'border-transparent text-[var(--text-muted)] hover:text-[var(--text-primary)]'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`analyst-panel-${tab}`} aria-labelledby={`analyst-tab-${tab}`}>
        {tab === 'insights' ? <MLInsights /> : <ManualAnalyzer />}
      </div>
    </div>
  )
}

export default MLAnalyst
