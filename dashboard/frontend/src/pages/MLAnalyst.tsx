import React, { useState } from 'react'
import { Brain, Search, AlertTriangle, CheckCircle2 } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { api } from '../api/axios'

export default function MLAnalyst() {
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('GET')
  const [body, setBody] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handlePredict = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url) {
      toast.error('URL is required')
      return
    }

    setLoading(true)
    setResult(null)
    try {
      // Use predict-and-suggest so it auto-creates pending rules for anomalies
      const response = await api.post('/ml/predict-and-suggest', { url, method, body })
      setResult(response.data.prediction)
      
      if (response.data.suggested_rule) {
        toast.success(`Anomaly detected! Suggested rule #${response.data.suggested_rule.rule_id.substring(0,8)} sent for approval.`, {
          duration: 6000
        })
      } else {
        toast.success('Analysis complete')
      }
    } catch (error: any) {
      toast.error(error.response?.data?.detail || error.message || 'An error occurred during analysis')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <TopBar title="ML Analyst" subtitle="Test and analyze requests using the Machine Learning model" />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card className="animate-fade-in-up stagger-1">
          <CardHeader title="Analyze Request" subtitle="Submit a request payload for ML analysis" />
          <form onSubmit={handlePredict} className="space-y-4">
            <div>
              <label className="block text-[11px] font-bold text-white/25 uppercase tracking-[0.08em] mb-2">HTTP Method</label>
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="w-full bg-white/[0.02] border border-white/[0.08] rounded-xl px-4 py-2.5 text-[13px] text-white outline-none focus:border-accent/40 focus:shadow-[0_0_0_3px_rgba(102,126,234,0.08)] transition-all"
              >
                {['GET', 'POST', 'PUT', 'DELETE'].map(m => (
                  <option key={m} value={m} className="bg-bg-surface">{m}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-bold text-white/25 uppercase tracking-[0.08em] mb-2">Target URL / Path</label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="e.g., /login?user=admin"
                className="w-full bg-white/[0.02] border border-white/[0.08] rounded-xl px-4 py-2.5 text-[13px] text-white placeholder:text-white/15 outline-none focus:border-accent/40 focus:shadow-[0_0_0_3px_rgba(102,126,234,0.08)] transition-all"
              />
            </div>

            <div>
              <label className="block text-[11px] font-bold text-white/25 uppercase tracking-[0.08em] mb-2">Request Body (Optional)</label>
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder='e.g., {"username": "admin"}'
                className="w-full bg-white/[0.02] border border-white/[0.08] rounded-xl px-4 py-3 text-[13px] text-white placeholder:text-white/15 outline-none focus:border-accent/40 focus:shadow-[0_0_0_3px_rgba(102,126,234,0.08)] transition-all h-32 resize-none font-mono"
              />
            </div>

            <div className="pt-1">
              <Button type="submit" className="w-full" isLoading={loading} icon={!loading ? <Search size={16} /> : undefined}>
                Analyze Payload
              </Button>
            </div>
          </form>
        </Card>

        <Card className="animate-fade-in-up stagger-2">
          <CardHeader title="Analysis Result" subtitle="ML model prediction output" />
          {!result && !loading && (
            <div className="flex flex-col items-center justify-center h-64 text-white/15">
              <Brain size={48} className="mb-4 opacity-30" />
              <p className="text-[13px] font-medium">Submit a request to see results here.</p>
            </div>
          )}
          
          {loading && (
            <div className="flex items-center justify-center h-64">
              <div className="w-8 h-8 border-2 border-accent/15 border-t-accent rounded-full animate-spin" />
            </div>
          )}

          {result && (
            <div className="space-y-5 animate-scale-in">
              <div className={`p-5 rounded-xl flex items-center justify-between ${result.is_anomaly ? 'bg-danger/[0.06] border border-danger/[0.1]' : 'bg-success/[0.06] border border-success/[0.1]'}`}>
                <div className="flex items-center gap-3.5">
                  {result.is_anomaly ? (
                    <div className="w-11 h-11 rounded-xl bg-danger/[0.1] flex items-center justify-center text-danger">
                      <AlertTriangle size={22} />
                    </div>
                  ) : (
                    <div className="w-11 h-11 rounded-xl bg-success/[0.1] flex items-center justify-center text-success">
                      <CheckCircle2 size={22} />
                    </div>
                  )}
                  <div>
                    <h3 className={`text-[16px] font-extrabold font-heading ${result.is_anomaly ? 'text-danger' : 'text-success'}`}>
                      {result.status}
                    </h3>
                    <p className="text-[12px] text-white/25 mt-0.5 font-medium">
                      Confidence: {result.confidence}
                    </p>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.04]">
                  <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.08em] mb-1.5">Attack Probability</p>
                  <p className="text-[20px] font-extrabold font-mono text-white/80 font-heading">{(result.attack_probability * 100).toFixed(2)}%</p>
                </div>
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.04]">
                  <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.08em] mb-1.5">Anomaly Score</p>
                  <p className="text-[20px] font-extrabold font-mono text-white/80 font-heading">{result.anomaly_score.toFixed(4)}</p>
                </div>
              </div>

              {result.features && (
                <div>
                  <h4 className="text-[10px] font-bold text-white/20 mb-3 uppercase tracking-[0.08em]">Extracted Features</h4>
                  <div className="bg-black/20 rounded-xl border border-white/[0.04] p-4 overflow-x-auto">
                    <pre className="text-[11px] text-accent-light/30 font-mono leading-relaxed">
                      {JSON.stringify(result.features, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
