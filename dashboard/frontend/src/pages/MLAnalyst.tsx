import React, { useState } from 'react'
import { Brain, Search, AlertTriangle, CheckCircle2, Sparkles, Cpu, MessageSquareText, ChevronDown, ChevronUp } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { api } from '../api/axios'

interface AttributionEntry {
  feature: string
  value: number
  contribution: number
}

interface PredictionResult {
  is_anomaly?: boolean
  status?: string
  confidence?: string | number
  attack_probability?: number
  anomaly_score?: number
  features?: Record<string, unknown>
  attribution?: AttributionEntry[]
  attribution_baseline?: number
  explanation?: string
}

// Renders "n%" only for a genuine finite number; anything else (missing,
// null, NaN) falls back to a placeholder instead of ever rendering "NaN%".
const formatPercent = (value: unknown, digits = 2): string =>
  typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(digits)}%` : 'N/A'

const formatNumber = (value: unknown, digits = 4): string =>
  typeof value === 'number' && Number.isFinite(value) ? value.toFixed(digits) : 'N/A'

const TOP_ATTRIBUTION_COUNT = 5

export const MLAnalyst: React.FC = () => {
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('GET')
  const [body, setBody] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<PredictionResult | null>(null)
  const [showAllAttribution, setShowAllAttribution] = useState(false)

  const handlePredict = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url) {
      toast.error('URL target path is required')
      return
    }

    setLoading(true)
    setResult(null)
    setShowAllAttribution(false)
    try {
      const response = await api.post('/ml/predict-and-suggest', { url, method, body })
      setResult(response.data.prediction)

      if (response.data.suggested_rule) {
        toast.success(
          `Anomaly confirmed! Suggested SecRule #${response.data.suggested_rule.rule_id.substring(
            0,
            8
          )} sent to Approval Queue.`,
          { duration: 6000 }
        )
      } else {
        toast.success('ML Payload classification complete')
      }
    } catch (error: any) {
      toast.error(error.response?.data?.detail || error.message || 'An error occurred during ML inference')
    } finally {
      setLoading(false)
    }
  }

  // attribution is sorted by |contribution| descending already; take the
  // top few unless the reader asked to expand to the full set.
  const attribution = result?.attribution ?? []
  const visibleAttribution = showAllAttribution ? attribution : attribution.slice(0, TOP_ATTRIBUTION_COUNT)
  const maxAbsContribution = attribution.reduce((max, a) => Math.max(max, Math.abs(a.contribution)), 0) || 1

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title="AI Threat Analyst & Payload Simulator"
        subtitle="Test raw HTTP requests against the Random Forest & Isolation Forest ML anomaly model"
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Simulator Input Form */}
        <div className="dash-card p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 pb-3.5 mb-4 border-b border-[var(--bg-border-subtle)]">
              <Cpu size={16} className="text-violet-500" />
              <h3 className="text-[13.5px] font-bold text-[var(--text-primary)] font-mono m-0">
                Payload Inspector & Simulator
              </h3>
            </div>

            <form onSubmit={handlePredict} className="space-y-4 text-[12.5px]">
              <div>
                <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1.5">
                  HTTP Method
                </label>
                <div className="grid grid-cols-4 gap-2">
                  {['GET', 'POST', 'PUT', 'DELETE'].map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setMethod(m)}
                      className={`py-1.5 text-[12px] font-mono font-bold rounded-md border transition-all cursor-pointer ${
                        method === m
                          ? 'bg-violet-500/15 text-violet-400 border-violet-500/40 shadow-sm'
                          : 'bg-[var(--bg-primary)] text-[var(--text-secondary)] border-[var(--bg-border)] hover:bg-[var(--bg-hover)]'
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1.5">
                  Target URL / Request Path
                </label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="e.g. /vulnerabilities/sqli/?id=1' UNION SELECT null, user() --"
                  className="w-full dash-input font-mono text-[12px]"
                />
              </div>

              <div>
                <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1.5">
                  Request Body (JSON / Form / Raw)
                </label>
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder='e.g. {"username": "admin\" OR 1=1 --", "password": "x"}'
                  className="w-full dash-input font-mono text-[12px] h-28 resize-none"
                />
              </div>

              <div className="pt-2">
                <Button
                  type="submit"
                  className="w-full bg-violet-600 hover:bg-violet-700 text-white font-mono font-semibold"
                  isLoading={loading}
                  icon={<Search size={14} />}
                >
                  Run Neural Model Inference
                </Button>
              </div>
            </form>
          </div>
        </div>

        {/* Prediction Results Card */}
        <div className="dash-card p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 pb-3.5 mb-4 border-b border-[var(--bg-border-subtle)]">
              <Sparkles size={16} className="text-violet-500" />
              <h3 className="text-[13.5px] font-bold text-[var(--text-primary)] font-mono m-0">
                Inference Classification Output
              </h3>
            </div>

            {!result && !loading && (
              <div className="flex flex-col items-center justify-center h-64 text-[var(--text-muted)] text-center space-y-2">
                <Brain size={42} className="opacity-30 text-violet-400" />
                <p className="text-[12.5px] font-mono">
                  Submit a payload on the left to analyze with ML features.
                </p>
              </div>
            )}

            {loading && (
              <div className="flex flex-col items-center justify-center h-64 space-y-3">
                <div className="w-8 h-8 border-2 border-violet-500/20 border-t-violet-500 rounded-full animate-spin" />
                <p className="text-[12px] font-mono text-[var(--text-muted)]">
                  Decoding payload & extracting keyword, character and structural features...
                </p>
              </div>
            )}

            {result && (
              <div className="space-y-4 animate-fade-in">
                <div
                  className={`p-4 rounded-xl flex items-center justify-between border ${
                    result.is_anomaly
                      ? 'bg-red-500/10 border-red-500/30'
                      : 'bg-emerald-500/10 border-emerald-500/30'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                        result.is_anomaly ? 'bg-red-500/20 text-red-500' : 'bg-emerald-500/20 text-emerald-500'
                      }`}
                    >
                      {result.is_anomaly ? <AlertTriangle size={20} /> : <CheckCircle2 size={20} />}
                    </div>
                    <div>
                      <h3
                        className={`text-[15px] font-bold font-mono m-0 ${
                          result.is_anomaly ? 'text-red-500' : 'text-emerald-500'
                        }`}
                      >
                        {result.status}
                      </h3>
                      <p className="text-[11.5px] text-[var(--text-secondary)] m-0 mt-0.5 font-mono">
                        Classification Confidence: <strong className="text-[var(--text-primary)]">{result.confidence}</strong>
                      </p>
                    </div>
                  </div>
                </div>

                {/* Thai explanation -- the headline output of T9/T10, not a footnote.
                    Absent entirely on rare failure (api/ml.py drops the key rather
                    than 500ing); that is a normal case, not an error, so it simply
                    isn't rendered. */}
                {result.explanation && (
                  <div className="p-4 rounded-xl bg-violet-500/10 border border-violet-500/30">
                    <div className="flex items-center gap-2 mb-1.5">
                      <MessageSquareText size={15} className="text-violet-400" />
                      <span className="text-[10.5px] font-bold uppercase text-violet-400 font-mono">
                        Model Explanation
                      </span>
                    </div>
                    <p className="text-[13.5px] text-[var(--text-primary)] m-0 leading-relaxed">
                      {result.explanation}
                    </p>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3 font-mono">
                  <div className="p-3.5 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                    <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase block mb-1">
                      Attack Probability
                    </span>
                    <span className="text-[20px] font-bold text-[var(--text-primary)]">
                      {formatPercent(result.attack_probability)}
                    </span>
                  </div>

                  <div className="p-3.5 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                    <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase block mb-1">
                      Anomaly Vector Score
                    </span>
                    <span className="text-[20px] font-bold text-violet-400">
                      {formatNumber(result.anomaly_score)}
                    </span>
                  </div>
                </div>

                {/* Feature attribution -- may legitimately be absent (T9 could not
                    compute it); that is not an error state either. */}
                {attribution.length > 0 && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10.5px] font-bold uppercase text-[var(--text-muted)] font-mono">
                        Top Contributing Features
                      </span>
                      {typeof result.attribution_baseline === 'number' && (
                        <span className="text-[10px] font-mono text-[var(--text-muted)]">
                          baseline {formatNumber(result.attribution_baseline, 4)}
                        </span>
                      )}
                    </div>
                    <div className="bg-[var(--bg-primary)] rounded-lg border border-[var(--bg-border)] p-3 space-y-2">
                      {visibleAttribution.map((a) => {
                        const isPositive = a.contribution >= 0
                        const widthPct = Math.min(100, (Math.abs(a.contribution) / maxAbsContribution) * 100)
                        return (
                          <div key={a.feature} className="text-[11.5px] font-mono">
                            <div className="flex items-center justify-between mb-0.5">
                              <span className="text-[var(--text-secondary)]">{a.feature}</span>
                              <span className={isPositive ? 'text-red-500 font-bold' : 'text-emerald-500 font-bold'}>
                                {isPositive ? '+' : ''}
                                {a.contribution.toFixed(4)}
                              </span>
                            </div>
                            <div className="h-1.5 rounded-full bg-[var(--bg-border)] overflow-hidden">
                              <div
                                className={`h-full rounded-full ${isPositive ? 'bg-red-500' : 'bg-emerald-500'}`}
                                style={{ width: `${widthPct}%` }}
                              />
                            </div>
                          </div>
                        )
                      })}
                    </div>
                    {attribution.length > TOP_ATTRIBUTION_COUNT && (
                      <button
                        type="button"
                        onClick={() => setShowAllAttribution((v) => !v)}
                        className="mt-2 flex items-center gap-1 text-[11px] font-mono text-violet-400 hover:text-violet-300 cursor-pointer"
                      >
                        {showAllAttribution ? (
                          <>
                            <ChevronUp size={13} /> Show top {TOP_ATTRIBUTION_COUNT} only
                          </>
                        ) : (
                          <>
                            <ChevronDown size={13} /> Show all {attribution.length} features
                          </>
                        )}
                      </button>
                    )}
                  </div>
                )}

                {result.features && (
                  <div>
                    <span className="text-[10.5px] font-bold uppercase text-[var(--text-muted)] font-mono block mb-2">
                      Extracted Feature Map
                    </span>
                    <div className="bg-[var(--bg-primary)] rounded-lg border border-[var(--bg-border)] p-3 overflow-x-auto">
                      <pre className="text-[11px] font-mono text-[var(--text-secondary)] m-0">
                        {JSON.stringify(result.features, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default MLAnalyst
