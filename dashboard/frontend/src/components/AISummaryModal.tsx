import React, { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Sparkles, X, Send, Calendar, ShieldCheck, AlertTriangle, Copy, Check, BarChart3, Clock, ArrowRight } from 'lucide-react'
import { aiSummaryApi, SummarizeRangeResponse } from '../api/aiSummary'
import toast from 'react-hot-toast'
import { ReportText } from './ai/ReportText'
import { useT } from '../i18n'

interface AISummaryModalProps {
  isOpen: boolean
  onClose: () => void
}

export const AISummaryModal: React.FC<AISummaryModalProps> = ({ isOpen, onClose }) => {
  const [queryText, setQueryText] = useState('')
  const [startTime, setStartTime] = useState('')
  const [endTime, setEndTime] = useState('')
  const [result, setResult] = useState<SummarizeRangeResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const { t } = useT()

  const summaryMutation = useMutation({
    mutationFn: () => aiSummaryApi.summarizeRange(queryText, startTime, endTime),
    onSuccess: (data) => {
      setResult(data)
      toast.success(t('AI summary is ready', 'สรุปด้วย AI เสร็จแล้ว'))
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || t('Failed to generate summary', 'สรุปไม่สำเร็จ'))
    },
  })

  if (!isOpen) return null

  const handlePreset = (text: string) => {
    setQueryText(text)
    setStartTime('')
    setEndTime('')
    summaryMutation.mutate()
  }

  const handleCopy = () => {
    if (!result?.ai_executive_summary) return
    navigator.clipboard.writeText(result.ai_executive_summary)
    setCopied(true)
    toast.success(t('Copied report to clipboard', 'คัดลอกรายงานแล้ว'))
    setTimeout(() => setCopied(false), 2000)
  }

  const blockRate = result?.stats?.total_requests
    ? ((result.stats.blocked_attacks / result.stats.total_requests) * 100).toFixed(1)
    : '0'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 px-6 border-b border-[var(--bg-border-subtle)] flex items-center justify-between bg-[var(--bg-surface)]">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shadow-inner">
              <Sparkles size={20} />
            </div>
            <div>
              <h2 className="text-[16px] font-bold text-[var(--text-primary)] font-mono tracking-tight m-0">
                {t('Security event summary', 'สรุปเหตุการณ์ความปลอดภัย')}
              </h2>
              <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                {t('Attacks on the sites in this account for the chosen time range', 'การโจมตีของเว็บในบัญชีนี้ตามช่วงเวลาที่เลือก')}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t('Close', 'ปิด')}
            className="p-1.5 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {/* Natural language query input */}
          <div className="space-y-2">
            <label className="text-[12px] font-bold font-mono text-[var(--text-secondary)] block">
              {t('Time range', 'ช่วงเวลา')}
            </label>
            <div className="relative flex items-center">
              <input
                type="text"
                value={queryText}
                onChange={(e) => setQueryText(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && summaryMutation.mutate()}
                placeholder={t("e.g. 'last 3 days', 'yesterday to noon today'", "เช่น '3 วันล่าสุด', 'เมื่อวานถึงเที่ยงวันนี้'")}
                className="w-full pl-4 pr-28 py-3 rounded-xl bg-[var(--bg-surface)] border border-[var(--bg-border)] text-[13px] text-[var(--text-primary)] focus:outline-none focus:border-indigo-500 transition-colors shadow-inner"
              />
              <button
                type="button"
                onClick={() => summaryMutation.mutate()}
                disabled={summaryMutation.isPending}
                className="absolute right-2 px-4 py-1.8 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-[12px] flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer shadow-md"
              >
                {summaryMutation.isPending ? (
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <Send size={13} />
                    <span>{t('Summarise', 'สรุป')}</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Quick Presets */}
          <div className="flex items-center gap-2 flex-wrap text-[11.5px]">
            <span className="text-[var(--text-muted)] font-mono">{t('Or pick a quick range:', 'หรือเลือกช่วงด่วน:')}</span>
            {/* The query sent stays the Thai phrase the range parser is
                tested with; only the button label follows the language. */}
            {[
              { query: '24 ชั่วโมงล่าสุด', label: t('Last 24 hours', '24 ชั่วโมงล่าสุด') },
              { query: '3 วันล่าสุด', label: t('Last 3 days', '3 วันล่าสุด') },
              { query: '7 วันล่าสุด', label: t('Last 7 days', '7 วันล่าสุด') },
              { query: '30 วันล่าสุด', label: t('Last 30 days', '30 วันล่าสุด') },
            ].map((preset) => (
              <button
                key={preset.query}
                type="button"
                onClick={() => handlePreset(preset.query)}
                className="px-2.5 py-1 rounded-md bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-indigo-400 border border-[var(--bg-border)] font-mono transition-colors cursor-pointer"
              >
                {preset.label}
              </button>
            ))}
          </div>

          {/* Report Results */}
          {result && (
            <div className="space-y-4 pt-4 border-t border-[var(--bg-border-subtle)] animate-in fade-in slide-in-from-bottom-2 duration-200">
              {/* Range Banner & Stats */}
              <div className="flex items-center justify-between p-3.5 px-4 rounded-xl bg-indigo-500/10 border border-indigo-500/20">
                <div className="flex items-center gap-2 font-mono text-[12.5px] text-indigo-800 dark:text-indigo-300">
                  <Clock size={15} />
                  <span>{t('Analysed range:', 'ช่วงเวลาที่วิเคราะห์:')} <strong>{result.time_range.description}</strong></span>
                </div>
                <button
                  type="button"
                  onClick={handleCopy}
                  className="px-2.5 py-1 rounded bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-800 dark:text-indigo-200 font-mono text-[11px] flex items-center gap-1 transition-colors cursor-pointer"
                >
                  {copied ? <Check size={12} /> : <Copy size={12} />}
                  {copied ? t('Copied', 'คัดลอกแล้ว') : t('Copy report', 'คัดลอกรายงาน')}
                </button>
              </div>

              {/* Stat Metric Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3.5 rounded-xl bg-[var(--bg-surface)] border border-[var(--bg-border)]">
                  <span className="text-[11px] text-[var(--text-muted)] font-mono block">{t('Total requests', 'Request ทั้งหมด')}</span>
                  <span className="text-[20px] font-bold text-[var(--text-primary)] font-mono">
                    {result.stats.total_requests.toLocaleString()}
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-[var(--bg-surface)] border border-[var(--bg-border)]">
                  <span className="text-[11px] text-red-400 font-mono block">{t('Blocked attacks', 'การโจมตีที่ถูกบล็อก')}</span>
                  <span className="text-[20px] font-bold text-red-400 font-mono">
                    {result.stats.blocked_attacks.toLocaleString()}
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-[var(--bg-surface)] border border-[var(--bg-border)]">
                  <span className="text-[11px] text-emerald-400 font-mono block">{t('Block rate', 'อัตราการบล็อก')}</span>
                  <span className="text-[20px] font-bold text-emerald-400 font-mono">
                    {blockRate}%
                  </span>
                </div>
              </div>

              {/* AI findings and actions (ReportText) */}
              <div className="p-5 rounded-xl bg-[var(--bg-surface)] border border-[var(--bg-border)] space-y-3">
                <div className="flex items-center gap-2 text-indigo-400 font-bold text-[13px] font-mono border-b border-[var(--bg-border-subtle)] pb-2">
                  <Sparkles size={16} />
                  <span>{t('Findings and next steps', 'ข้อสังเกตและสิ่งที่ควรทำ')}</span>
                </div>
                <ReportText text={result.ai_executive_summary} className="text-[13px]" />
                <p className="m-0 text-[11px] text-[var(--text-muted)]">
                  {t('Written by AI from the logs of this range. The figures above come straight from the logs.', 'สรุปโดย AI จาก log ของช่วงนี้ ตัวเลขด้านบนมาจาก log โดยตรง')}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
