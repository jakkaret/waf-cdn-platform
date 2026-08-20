import React, { useState } from 'react'
import { Brain, Search, AlertTriangle, CheckCircle2, Sparkles, Terminal, Code, Cpu } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { api } from '../api/axios'

export const MLAnalyst: React.FC = () => {
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('GET')
  const [body, setBody] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handlePredict = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url) {
      toast.error('URL target path is required')
      return
    }

    setLoading(true)
    setResult(null)
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

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title="AI Threat Analyst & Payload Simulator"
        subtitle="Test raw HTTP requests against the Random Forest & Isolation Forest ML anomaly model"
        badge={
          <Badge color="purple" dot pulse>
            MODEL v2.1 ONLINE
          </Badge>
        }
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
                  Extracting n-grams & computing entropy vectors...
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

                <div className="grid grid-cols-2 gap-3 font-mono">
                  <div className="p-3.5 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                    <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase block mb-1">
                      Attack Probability
                    </span>
                    <span className="text-[20px] font-bold text-[var(--text-primary)]">
                      {(result.attack_probability * 100).toFixed(2)}%
                    </span>
                  </div>

                  <div className="p-3.5 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                    <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase block mb-1">
                      Anomaly Vector Score
                    </span>
                    <span className="text-[20px] font-bold text-violet-400">
                      {result.anomaly_score.toFixed(4)}
                    </span>
                  </div>
                </div>

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
