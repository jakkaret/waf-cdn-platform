import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, CheckCircle2, ScanSearch, ShieldQuestion } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { api } from '../api/axios'
import { useAuthStore } from '../store/authStore'
import { isOperator } from '../lib/permissions'
import { describeSuggestion, SuggestionSummary } from '../lib/mlRules'
import { detectorNote, formatPercent, Gen3Verdict, SAMPLE_REQUESTS, scoreBar, verdictView } from '../lib/mlAnalyst'

const METHODS = ['GET', 'POST', 'PUT', 'DELETE']

interface AnalysisResult {
  gen3: Gen3Verdict | null
  suggestion: SuggestionSummary | null
}

const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: 'text-[var(--danger)]',
  HIGH: 'text-[var(--warning)]',
  MEDIUM: 'text-[var(--text-secondary)]',
}

const sectionTitle = 'm-0 mb-2 text-[12.5px] font-medium text-[var(--text-secondary)]'

export const MLAnalyst: React.FC = () => {
  const { user } = useAuthStore()
  const canReview = isOperator(user)
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('GET')
  const [body, setBody] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [gen3Missing, setGen3Missing] = useState(false)

  const handlePredict = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) {
      toast.error('ใส่ URL หรือ path ของ request ก่อน')
      return
    }
    setLoading(true)
    setResult(null)
    setGen3Missing(false)
    try {
      // gen3 = score, threshold, detectors; suggestion = {engine, created, merged, reason}.
      // No Gen 3 model on the ML host answers 503 (shown as the error toast).
      const response = await api.post('/ml/predict-and-suggest', { url, method, body })
      setResult({
        gen3: response.data.gen3 ?? null,
        suggestion: response.data.suggestion ?? null,
      })
    } catch (error: any) {
      // "Gen 3 model unavailable" (api/ml.py _gen3_verdict): the ML host runs an older
      // service without Gen 3; explained in the result panel instead of a toast.
      const detail: string = error.response?.data?.detail || ''
      if (error.response?.status === 503 && detail.startsWith('Gen 3 model unavailable')) setGen3Missing(true)
      else toast.error(error.response?.data?.detail || error.message || 'วิเคราะห์ไม่สำเร็จ')
    } finally {
      setLoading(false)
    }
  }

  const fillSample = (s: (typeof SAMPLE_REQUESTS)[number]) => {
    setMethod(s.method)
    setUrl(s.url)
    setBody(s.body)
  }

  const gen3 = result?.gen3 ?? null
  const verdict = verdictView(gen3)
  const bar = verdict ? scoreBar(verdict.score, verdict.threshold) : null
  const suggestion = result ? describeSuggestion(result.suggestion) : null

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title="AI Security Analyst"
        subtitle="ทดสอบ HTTP request กับโมเดล Gen 3 ผลใช้วิเคราะห์เท่านั้น ไม่บล็อก traffic จริง"
      />

      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] gap-5 items-start">
        {/* Request form */}
        <form onSubmit={handlePredict} className="dash-card p-5 space-y-4">
          <h2 className="m-0 text-[14px] font-semibold text-[var(--text-primary)]">Request ที่จะวิเคราะห์</h2>

          <fieldset className="m-0 p-0 border-0">
            <legend className={sectionTitle}>Method</legend>
            <div className="inline-flex rounded-md border border-[var(--bg-border)] bg-[var(--bg-primary)] p-0.5">
              {METHODS.map((m) => (
                <button
                  key={m}
                  type="button"
                  aria-pressed={method === m}
                  onClick={() => setMethod(m)}
                  className={`h-8 px-3 rounded text-[12.5px] font-mono font-medium transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
                    method === m
                      ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-sm'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
          </fieldset>

          <div>
            <label htmlFor="analyst-url" className={`block ${sectionTitle}`}>URL / path พร้อม query</label>
            <input
              id="analyst-url"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="/products?id=1' OR '1'='1"
              spellCheck={false}
              className="w-full dash-input h-9 font-mono text-[12.5px]"
            />
          </div>

          <div>
            <label htmlFor="analyst-body" className={`block ${sectionTitle}`}>
              Body <span className="text-[var(--text-muted)] font-normal">(ไม่บังคับ: JSON, form หรือข้อความ)</span>
            </label>
            <textarea
              id="analyst-body"
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder='{"username": "admin\" OR 1=1 --"}'
              spellCheck={false}
              className="w-full dash-input font-mono text-[12.5px] h-28 resize-y"
            />
          </div>

          <div>
            <p className={sectionTitle}>ตัวอย่าง</p>
            <div className="flex flex-wrap gap-1.5">
              {SAMPLE_REQUESTS.map((s) => (
                <button
                  key={s.label}
                  type="button"
                  onClick={() => fillSample(s)}
                  className="h-7 rounded-full border border-[var(--bg-border)] bg-[var(--bg-surface)] px-2.5 text-[12px] text-[var(--text-secondary)] hover:border-[var(--bg-border-hover)] hover:text-[var(--text-primary)] cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          <Button type="submit" className="w-full h-9" isLoading={loading} icon={<ScanSearch size={15} />}>
            วิเคราะห์ request
          </Button>
        </form>

        {/* Result */}
        <section className="dash-card p-5 min-h-[20rem]" aria-live="polite">
          {!result && !loading && (
            <div className="flex h-full min-h-[18rem] flex-col items-center justify-center text-center">
              <ShieldQuestion size={36} className="text-[var(--text-dim)]" aria-hidden="true" />
              {gen3Missing ? (
                <>
                  <p className="mt-3 mb-1 text-[14px] font-medium text-[var(--text-primary)]">ML service ยังไม่มีโมเดล Gen 3</p>
                  <p className="m-0 max-w-sm text-[12.5px] text-[var(--text-muted)]">
                    หน้านี้ใช้ Gen 3 อย่างเดียว ต้อง deploy ML service เวอร์ชันที่มี Gen 3 ก่อน แล้วลองใหม่
                  </p>
                </>
              ) : (
                <>
                  <p className="mt-3 mb-1 text-[14px] font-medium text-[var(--text-primary)]">ยังไม่มีผลวิเคราะห์</p>
                  <p className="m-0 max-w-sm text-[12.5px] text-[var(--text-muted)]">
                    ใส่ request ทางซ้าย หรือเลือกตัวอย่าง แล้วกด "วิเคราะห์ request"
                  </p>
                </>
              )}
            </div>
          )}

          {loading && (
            <div className="flex min-h-[18rem] items-center justify-center gap-2 text-[13px] text-[var(--text-muted)]">
              <span className="h-4 w-4 rounded-full border-2 border-[var(--bg-border)] border-t-[var(--accent)] animate-spin" />
              กำลังวิเคราะห์...
            </div>
          )}

          {result && verdict && (
            <div className="space-y-5 animate-fade-in">
              {/* Verdict */}
              <div>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`flex h-9 w-9 items-center justify-center rounded-lg ${
                        verdict.isAttack ? 'bg-[var(--danger-subtle)] text-[var(--danger)]' : 'bg-[var(--success-subtle)] text-[var(--success)]'
                      }`}
                      aria-hidden="true"
                    >
                      {verdict.isAttack ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
                    </span>
                    <h2 className={`m-0 text-[17px] font-semibold ${verdict.isAttack ? 'text-[var(--danger)]' : 'text-[var(--success)]'}`}>
                      {verdict.title}
                    </h2>
                  </div>
                  <span
                    className="rounded-full border border-[var(--bg-border)] bg-[var(--bg-primary)] px-2.5 py-0.5 text-[12px] text-[var(--text-secondary)]"
                    title={gen3?.feature_set}
                  >
                    Gen 3 · shadow
                  </span>
                </div>

                {bar && (
                  <div className="mt-4">
                    <div className="flex items-baseline justify-between text-[12.5px]">
                      <span className="text-[var(--text-secondary)]">คะแนนการโจมตี</span>
                      <span className="tabular-nums">
                        <strong className="text-[15px] text-[var(--text-primary)]">{formatPercent(verdict.score)}</strong>
                        {verdict.threshold !== null && (
                          <span className="text-[var(--text-muted)]"> · เกณฑ์ {formatPercent(verdict.threshold)}</span>
                        )}
                      </span>
                    </div>
                    <div className="relative mt-1.5 h-2 rounded-full bg-[var(--bg-border)]">
                      <div
                        className={`h-full rounded-full ${verdict.isAttack ? 'bg-[var(--danger)]' : 'bg-[var(--success)]'}`}
                        style={{ width: `${bar.score}%` }}
                      />
                      {bar.threshold !== null && (
                        <span
                          className="absolute -top-1 h-4 w-0.5 rounded bg-[var(--text-primary)]"
                          style={{ left: `calc(${bar.threshold}% - 1px)` }}
                          aria-hidden="true"
                        />
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Detectors */}
              {gen3 && (
                <div>
                  <h3 className={sectionTitle}>สิ่งที่ตรวจพบ</h3>
                  {gen3.detectors && gen3.detectors.length > 0 && (
                    <ul className="m-0 mb-2 p-0 list-none divide-y divide-[var(--bg-border-subtle)] rounded-lg border border-[var(--bg-border)]">
                      {gen3.detectors.map((d) => (
                        <li key={d.detector} className="flex items-center justify-between gap-3 px-3 py-2">
                          <span className="min-w-0">
                            <span className="block text-[13px] font-medium text-[var(--text-primary)]">{d.attack_type}</span>
                            <span className="block truncate font-mono text-[11.5px] text-[var(--text-muted)]">{d.detector}</span>
                          </span>
                          <span className={`shrink-0 text-[12px] font-medium ${SEVERITY_TEXT[d.severity] ?? 'text-[var(--text-secondary)]'}`}>
                            {d.severity}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                  <p className="m-0 text-[12.5px] text-[var(--text-muted)]">{detectorNote(gen3)}</p>
                </div>
              )}

              {/* Rule suggestion outcome */}
              {suggestion && (
                <div
                  className={`flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2.5 text-[13px] ${
                    suggestion.queued
                      ? 'border-[var(--accent-border)] bg-[var(--accent-subtle)] text-[var(--text-primary)]'
                      : 'border-[var(--bg-border)] bg-[var(--bg-primary)] text-[var(--text-secondary)]'
                  }`}
                >
                  <span>{suggestion.text}</span>
                  {suggestion.queued && canReview && (
                    <Link
                      to="/ml-rules"
                      className="inline-flex items-center gap-1 font-medium text-[var(--accent)] hover:text-[var(--accent-hover)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] rounded"
                    >
                      เปิด ML anomaly rules <ArrowRight size={14} />
                    </Link>
                  )}
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

export default MLAnalyst
