import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Trash2 } from 'lucide-react'
import {
  addSiteRateRule,
  deleteSiteRateRule,
  getSiteRateRules,
  getSiteThrottled,
  SiteRateRule,
  SiteRateRuleInput,
  updateSiteRateRule,
} from '../api/siteAccess'
import { looksLikePathPattern, rateText } from '../lib/siteAccess'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { LoadingSpinner } from './ui/LoadingSpinner'
import { useT } from '../i18n'

interface Props {
  originId: string
  /** Owner or Editor. Viewers get a read-only view. */
  canEdit: boolean
}

const METHODS = ['ALL', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE']
const EMPTY: SiteRateRuleInput = { name: '', path_pattern: '/login', method: 'POST', limit_count: 10, window_seconds: 60 }

const errText = (e: any, fallback: string) => {
  const detail = e?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export const OriginRateLimits: React.FC<Props> = ({ originId, canEdit }) => {
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<SiteRateRuleInput>(EMPTY)
  const { t } = useT()
  const key = ['site-rate-limits', originId]

  const { data: rules, isLoading } = useQuery({ queryKey: key, queryFn: () => getSiteRateRules(originId) })
  const { data: throttled } = useQuery({
    queryKey: ['site-throttled', originId],
    queryFn: () => getSiteThrottled(originId),
    refetchInterval: 15000,
  })

  const refresh = () => queryClient.invalidateQueries({ queryKey: key })

  const addMutation = useMutation({
    mutationFn: () => addSiteRateRule(originId, { ...form, name: form.name.trim(), path_pattern: form.path_pattern.trim() }),
    onSuccess: () => {
      refresh()
      setForm(EMPTY)
      setShowForm(false)
      toast.success(t('Rate limit added', 'เพิ่ม rate limit แล้ว'))
    },
    onError: (e) => toast.error(errText(e, t('Failed to add the rate limit', 'เพิ่ม rate limit ไม่สำเร็จ'))),
  })

  const toggleMutation = useMutation({
    mutationFn: (rule: SiteRateRule) => updateSiteRateRule(originId, rule.id, { enabled: !rule.enabled }),
    onSuccess: refresh,
    onError: (e) => toast.error(errText(e, t('Failed to update the rate limit', 'อัปเดต rate limit ไม่สำเร็จ'))),
  })

  const deleteMutation = useMutation({
    mutationFn: (ruleId: string) => deleteSiteRateRule(originId, ruleId),
    onSuccess: () => {
      refresh()
      toast.success(t('Rate limit removed', 'ลบ rate limit แล้ว'))
    },
    onError: (e) => toast.error(errText(e, t('Failed to remove the rate limit', 'ลบ rate limit ไม่สำเร็จ'))),
  })

  const formOk = form.name.trim() !== '' && looksLikePathPattern(form.path_pattern)
    && form.limit_count >= 1 && form.limit_count <= 100000 && form.window_seconds >= 1 && form.window_seconds <= 3600
  const ruleName = (id: string) => rules?.find((r) => r.id === id)?.name ?? t('Platform limit', 'limit ของแพลตฟอร์ม')
  const inputClass = 'w-full dash-input font-mono'
  const labelClass = 'text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block'

  return (
    <div className="space-y-6">
      <section className="space-y-3">
        <div className="flex justify-between items-center gap-3">
          <div>
            <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">Rate limit</h2>
            <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
              {t(
                "Limit how many requests one visitor IP can send to a path on this origin's domains. Over the limit the visitor gets 429 until the window ends. Each domain counts on its own; platform-wide limits still apply.",
                'จำกัดจำนวน request ที่ IP หนึ่งส่งไปยัง path บนโดเมนของ origin นี้ได้ เกินแล้วจะได้ 429 จนกว่าช่วงเวลาจะหมด แต่ละโดเมนนับแยกกัน และ limit ของแพลตฟอร์มยังมีผลอยู่',
              )}
            </p>
          </div>
          {canEdit && (
            <Button variant={showForm ? 'secondary' : 'brand'} onClick={() => setShowForm((s) => !s)}>
              {showForm ? t('Cancel', 'ยกเลิก') : t('+ Add limit', '+ เพิ่ม limit')}
            </Button>
          )}
        </div>

        {canEdit && showForm && (
          <form
            className="dash-card p-5 border-l-2 border-l-orange-500 bg-orange-500/[0.02] grid grid-cols-1 md:grid-cols-2 gap-3 text-[12px]"
            onSubmit={(e) => {
              e.preventDefault()
              if (formOk) addMutation.mutate()
            }}
          >
            <div className="md:col-span-2">
              <label className={labelClass}>{t('Name', 'ชื่อ')}</label>
              <input
                className={inputClass}
                maxLength={80}
                placeholder={t('e.g. Login guard', 'เช่น กันยิงหน้าล็อกอิน')}
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div>
              <label className={labelClass}>Path</label>
              <input
                className={inputClass}
                placeholder={t('/login, /api/*, or *', '/login, /api/* หรือ *')}
                value={form.path_pattern}
                onChange={(e) => setForm((f) => ({ ...f, path_pattern: e.target.value }))}
              />
            </div>
            <div>
              <label className={labelClass}>Method</label>
              <select
                className={inputClass}
                value={form.method}
                onChange={(e) => setForm((f) => ({ ...f, method: e.target.value }))}
              >
                {METHODS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelClass}>{t('Requests', 'จำนวน request')}</label>
              <input
                type="number"
                min={1}
                max={100000}
                className={inputClass}
                value={form.limit_count}
                onChange={(e) => setForm((f) => ({ ...f, limit_count: Number(e.target.value) }))}
              />
            </div>
            <div>
              <label className={labelClass}>{t('Per (seconds)', 'ต่อ (วินาที)')}</label>
              <input
                type="number"
                min={1}
                max={3600}
                className={inputClass}
                value={form.window_seconds}
                onChange={(e) => setForm((f) => ({ ...f, window_seconds: Number(e.target.value) }))}
              />
            </div>
            <div className="md:col-span-2 flex justify-end">
              <Button type="submit" disabled={!formOk} isLoading={addMutation.isPending}>
                {t('Add limit', 'เพิ่ม limit')}
              </Button>
            </div>
          </form>
        )}

        {isLoading ? (
          <LoadingSpinner />
        ) : (
          <div className="dash-card overflow-x-auto">
            <table className="dash-table">
              <thead>
                <tr>
                  <th>{t('Name', 'ชื่อ')}</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Limit</th>
                  <th>{t('On', 'เปิด')}</th>
                  {canEdit && <th></th>}
                </tr>
              </thead>
              <tbody>
                {!rules || rules.length === 0 ? (
                  <tr>
                    <td colSpan={canEdit ? 6 : 5} className="py-6 text-center text-[var(--text-muted)] font-mono text-[12px]">
                      {t('No rate limits for this origin.', 'origin นี้ยังไม่มี rate limit')}
                    </td>
                  </tr>
                ) : (
                  rules.map((rule) => (
                    <tr key={rule.id}>
                      <td className="font-mono font-bold">{rule.name}</td>
                      <td>
                        <Badge color="gray">{rule.method}</Badge>
                      </td>
                      <td className="font-mono text-[12px]">{rule.path_pattern}</td>
                      <td className="font-mono text-[12px]">{rateText(rule.limit_count, rule.window_seconds)}</td>
                      <td>
                        <input
                          type="checkbox"
                          checked={!!rule.enabled}
                          disabled={!canEdit || toggleMutation.isPending}
                          onChange={() => toggleMutation.mutate(rule)}
                          aria-label={rule.enabled ? t(`Turn ${rule.name} off`, `ปิด ${rule.name}`) : t(`Turn ${rule.name} on`, `เปิด ${rule.name}`)}
                        />
                      </td>
                      {canEdit && (
                        <td className="text-right">
                          <button
                            onClick={() => deleteMutation.mutate(rule.id)}
                            disabled={deleteMutation.isPending}
                            className="text-red-500 hover:text-red-400 cursor-pointer"
                            aria-label={t(`Delete ${rule.name}`, `ลบ ${rule.name}`)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </td>
                      )}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="space-y-3">
        <div>
          <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">{t('Visitors being counted', 'ผู้เข้าชมที่กำลังถูกนับ')}</h2>
          <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
            {t(
              "IPs with an open counter on this origin's domains right now, from its own limits and the platform's.",
              'IP ที่กำลังถูกนับบนโดเมนของ origin นี้ตอนนี้ ทั้งจาก limit ของ origin เองและของแพลตฟอร์ม',
            )}
          </p>
        </div>
        <div className="dash-card overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>{t('Domain', 'โดเมน')}</th>
                <th>Limit</th>
                <th>{t('Requests', 'Request')}</th>
                <th>{t('Resets in', 'รีเซ็ตใน')}</th>
                <th>{t('Status', 'สถานะ')}</th>
              </tr>
            </thead>
            <tbody>
              {!throttled || throttled.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    {t('Nobody is near a limit.', 'ยังไม่มีใครใกล้ถึง limit')}
                  </td>
                </tr>
              ) : (
                throttled.map((c) => (
                  <tr key={`${c.rule_id}|${c.host}|${c.ip}`}>
                    <td className="font-mono font-bold">{c.ip}</td>
                    <td className="font-mono text-[12px]">{c.host}</td>
                    <td className="text-[12px]">{ruleName(c.rule_id)}</td>
                    <td className="font-mono text-[12px]">{c.request_count}</td>
                    <td className="font-mono text-[12px]">{c.ttl_seconds}s</td>
                    <td>
                      <Badge color={c.status === 'throttled' ? 'danger' : 'gray'}>
                        {c.status === 'throttled' ? t('Throttled', 'ถูกจำกัด') : t('Counting', 'กำลังนับ')}
                      </Badge>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
