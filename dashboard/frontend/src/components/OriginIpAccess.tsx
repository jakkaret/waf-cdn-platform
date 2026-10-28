import React, { useEffect, useId, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Trash2 } from 'lucide-react'
import { addSiteIpRule, deleteSiteIpRule, getSiteIpRules, SiteIpRuleInput } from '../api/siteAccess'
import { DURATIONS, looksLikeIp } from '../lib/siteAccess'
import { BKK_LABEL, formatBkkDateTime } from '../lib/time'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { ConfirmDialog } from './ui/ConfirmDialog'
import { LoadingSpinner } from './ui/LoadingSpinner'
import { useT } from '../i18n'

interface Props {
  originId: string
  /** Owner or Editor. Viewers get a read-only view. */
  canEdit: boolean
  /** From a "Block IP" link (Alerts, dashboard, logs): fills the form, nothing is saved until confirmed. */
  prefillIp?: string | null
  prefillNote?: string | null
}

const EMPTY: SiteIpRuleInput = { ip: '', action: 'block', note: '', hours: null }

const errText = (e: any, fallback: string) => {
  const detail = e?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export const OriginIpAccess: React.FC<Props> = ({ originId, canEdit, prefillIp, prefillNote }) => {
  const queryClient = useQueryClient()
  const fid = useId()
  const [form, setForm] = useState<SiteIpRuleInput>(EMPTY)
  const [confirming, setConfirming] = useState(false)
  const { t } = useT()
  const key = ['site-ip-rules', originId]

  // A prefill only fills the form; the person still reviews and confirms.
  useEffect(() => {
    if (prefillIp) setForm({ ...EMPTY, ip: prefillIp, note: prefillNote ?? '' })
  }, [prefillIp, prefillNote])

  const { data: rules, isLoading, isError } = useQuery({ queryKey: key, queryFn: () => getSiteIpRules(originId) })

  const addMutation = useMutation({
    mutationFn: () => addSiteIpRule(originId, { ...form, ip: form.ip.trim(), note: form.note?.trim() }),
    onSuccess: (rule) => {
      queryClient.invalidateQueries({ queryKey: key })
      setForm(EMPTY)
      toast.success(
        rule.action === 'block'
          ? t(`${rule.ip} blocked on this origin`, `บล็อก ${rule.ip} ใน origin นี้แล้ว`)
          : t(`${rule.ip} allowed on this origin`, `อนุญาต ${rule.ip} ใน origin นี้แล้ว`),
      )
    },
    onError: (e) => toast.error(errText(e, t('Could not add the IP. Nothing was changed.', 'เพิ่ม IP ไม่สำเร็จ ยังไม่มีอะไรเปลี่ยน'))),
    onSettled: () => setConfirming(false),
  })

  const deleteMutation = useMutation({
    mutationFn: (ruleId: number) => deleteSiteIpRule(originId, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: key })
      toast.success(t('Removed', 'ลบแล้ว'))
    },
    onError: (e) => toast.error(errText(e, t('Could not remove the IP', 'ลบ IP ไม่สำเร็จ'))),
  })

  const ipOk = looksLikeIp(form.ip)
  const existing = (rules ?? []).find((r) => r.ip === form.ip.trim())
  const durationItem = DURATIONS.find((d) => (d.hours ?? null) === (form.hours ?? null))
  const duration = durationItem ? t(durationItem.label, durationItem.labelTh) : t('Permanent', 'ถาวร')
  const inputClass = 'w-full dash-input font-mono'
  const labelClass = 'text-[12px] font-medium text-[var(--text-secondary)] mb-1 block'

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-[16px] font-semibold text-[var(--text-primary)] m-0">{t('IP access', 'การเข้าถึงตาม IP')}</h2>
        <p className="text-[13px] text-[var(--text-muted)] m-0 mt-0.5 max-w-[80ch]">
          {t(
            "Block or always allow an IP address or range on this origin's domains only. Blocked visitors get 403 at the edge. Allowed visitors skip the WAF checks for this origin, so allow only addresses you trust. The platform's own block list still applies on top.",
            'บล็อกหรืออนุญาต IP หรือช่วง IP เฉพาะโดเมนของ origin นี้ ผู้ที่ถูกบล็อกจะได้ 403 ที่ edge ส่วนผู้ที่ได้รับอนุญาตจะข้ามการตรวจของ WAF สำหรับ origin นี้ จึงควรอนุญาตเฉพาะที่อยู่ที่ไว้ใจได้ รายการบล็อกของแพลตฟอร์มยังมีผลซ้อนอยู่ด้วย',
          )}
        </p>
      </div>

      {prefillIp && !canEdit && (
        <p role="note" className="m-0 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] px-4 py-3 text-[13px] text-[var(--text-secondary)]">
          {t(
            'You can view this list but not change it. Ask an Owner or Editor of this origin to block',
            'คุณดูรายการนี้ได้แต่แก้ไขไม่ได้ ให้ Owner หรือ Editor ของ origin นี้บล็อก',
          )}{' '}
          <span className="font-mono">{prefillIp}</span>.
        </p>
      )}

      {canEdit && (
        <form
          className="dash-card p-5 space-y-3 text-[12.5px]"
          onSubmit={(e) => {
            e.preventDefault()
            if (!ipOk) return
            // Blocking affects real visitors at once: review first.
            if (form.action === 'block') setConfirming(true)
            else addMutation.mutate()
          }}
        >
          {prefillIp && (
            <p className="m-0 text-[13px] text-[var(--text-secondary)]">
              {t('Filled in from the event you were looking at. Check the details, then add the rule.', 'กรอกให้จากเหตุการณ์ที่คุณเปิดดูอยู่ ตรวจรายละเอียดแล้วจึงเพิ่มกฎ')}
            </p>
          )}
          <div className="grid grid-cols-1 md:grid-cols-[2fr_1fr_1fr_2fr_auto] gap-3 items-end">
            <div>
              <label htmlFor={`${fid}-ip`} className={labelClass}>{t('IP or CIDR', 'IP หรือ CIDR')}</label>
              <input
                id={`${fid}-ip`}
                className={inputClass}
                placeholder={t('198.51.100.7 or 192.0.2.0/24', '198.51.100.7 หรือ 192.0.2.0/24')}
                value={form.ip}
                aria-invalid={form.ip.trim() !== '' && !ipOk}
                aria-describedby={`${fid}-ip-help`}
                onChange={(e) => setForm((f) => ({ ...f, ip: e.target.value }))}
              />
            </div>
            <div>
              <label htmlFor={`${fid}-action`} className={labelClass}>{t('Action', 'การดำเนินการ')}</label>
              <select
                id={`${fid}-action`}
                className={inputClass}
                value={form.action}
                onChange={(e) => setForm((f) => ({ ...f, action: e.target.value as SiteIpRuleInput['action'] }))}
              >
                <option value="block">{t('Block', 'บล็อก')}</option>
                <option value="allow">{t('Allow', 'อนุญาต')}</option>
              </select>
            </div>
            <div>
              <label htmlFor={`${fid}-hours`} className={labelClass}>{t('Duration', 'ระยะเวลา')}</label>
              <select
                id={`${fid}-hours`}
                className={inputClass}
                value={form.hours ?? ''}
                onChange={(e) => setForm((f) => ({ ...f, hours: e.target.value ? Number(e.target.value) : null }))}
              >
                {DURATIONS.map((d) => (
                  <option key={d.label} value={d.hours ?? ''}>
                    {t(d.label, d.labelTh)}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor={`${fid}-note`} className={labelClass}>{t('Note', 'หมายเหตุ')}</label>
              <input
                id={`${fid}-note`}
                className={inputClass}
                maxLength={200}
                placeholder={t('optional', 'ไม่บังคับ')}
                value={form.note}
                onChange={(e) => setForm((f) => ({ ...f, note: e.target.value }))}
              />
            </div>
            <Button type="submit" variant={form.action === 'block' ? 'brand' : 'primary'} disabled={!ipOk} isLoading={addMutation.isPending}>
              {form.action === 'block' ? t('Review block', 'ตรวจก่อนบล็อก') : t('Add', 'เพิ่ม')}
            </Button>
          </div>
          <p id={`${fid}-ip-help`} className="m-0 text-[12px]">
            {form.ip.trim() !== '' && !ipOk ? (
              <span className="text-red-600 dark:text-red-400">{t('Enter an IPv4 or IPv6 address, or a CIDR range.', 'กรอกที่อยู่ IPv4 หรือ IPv6 หรือช่วง CIDR')}</span>
            ) : existing ? (
              <span className="text-amber-700 dark:text-amber-400">
                {existing.action === 'block'
                  ? t(`${existing.ip} is already on this list (blocked).`, `${existing.ip} อยู่ในรายการนี้แล้ว (บล็อก)`)
                  : t(`${existing.ip} is already on this list (allowed).`, `${existing.ip} อยู่ในรายการนี้แล้ว (อนุญาต)`)}
              </span>
            ) : (
              <span className="text-[var(--text-muted)]">&nbsp;</span>
            )}
          </p>
        </form>
      )}

      {isLoading ? (
        <LoadingSpinner />
      ) : isError ? (
        <p className="m-0 text-[13px] text-red-600 dark:text-red-400">{t("Could not load this origin's IP list. Reload to try again.", 'โหลดรายการ IP ของ origin นี้ไม่สำเร็จ รีโหลดเพื่อลองใหม่')}</p>
      ) : (
        <div className="dash-card overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>{t('IP / range', 'IP / ช่วง')}</th>
                <th>{t('Action', 'การดำเนินการ')}</th>
                <th>{t('Note', 'หมายเหตุ')}</th>
                <th>{t(`Expires (${BKK_LABEL})`, 'หมดอายุ (เวลากรุงเทพฯ)')}</th>
                <th>{t('Added by', 'เพิ่มโดย')}</th>
                {canEdit && <th><span className="sr-only">{t('Remove', 'ลบ')}</span></th>}
              </tr>
            </thead>
            <tbody>
              {!rules || rules.length === 0 ? (
                <tr>
                  <td colSpan={canEdit ? 6 : 5} className="py-6 text-center text-[var(--text-muted)] text-[13px]">
                    {t('No IPs listed for this origin.', 'ยังไม่มี IP ในรายการของ origin นี้')}
                  </td>
                </tr>
              ) : (
                rules.map((rule) => (
                  <tr key={rule.id}>
                    <td className="font-mono font-semibold">{rule.ip}</td>
                    <td>
                      <Badge color={rule.action === 'block' ? 'danger' : 'success'}>
                        {rule.action === 'block' ? t('Block', 'บล็อก') : t('Allow', 'อนุญาต')}
                      </Badge>
                    </td>
                    <td className="text-[12.5px] text-[var(--text-secondary)]">{rule.note || '—'}</td>
                    <td className="font-mono text-[11.5px]">
                      {rule.expires_at ? formatBkkDateTime(rule.expires_at) : t('Never', 'ไม่หมดอายุ')}
                    </td>
                    <td className="text-[12px] text-[var(--text-muted)]">{rule.created_by || '—'}</td>
                    {canEdit && (
                      <td className="text-right">
                        <button
                          onClick={() => deleteMutation.mutate(rule.id)}
                          disabled={deleteMutation.isPending}
                          className="p-1 rounded text-red-600 dark:text-red-400 hover:bg-red-500/10 cursor-pointer"
                          aria-label={t(`Remove ${rule.ip}`, `ลบ ${rule.ip}`)}
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

      <ConfirmDialog
        open={confirming}
        onCancel={() => setConfirming(false)}
        onConfirm={() => {
          if (!addMutation.isPending) addMutation.mutate()
        }}
        title={t(`Block ${form.ip.trim()}?`, `บล็อก ${form.ip.trim()}?`)}
        message={t(
          `Every request from ${form.ip.trim()} to this origin's domains will get 403 at the edge (${duration.toLowerCase()}). This applies as soon as you confirm. Check that the address is not your own, a monitoring service or a shared proxy.`,
          `ทุก request จาก ${form.ip.trim()} ไปยังโดเมนของ origin นี้จะได้ 403 ที่ edge (${duration}) มีผลทันทีที่ยืนยัน ตรวจให้แน่ใจว่าไม่ใช่ที่อยู่ของคุณเอง ระบบ monitoring หรือ proxy ที่ใช้ร่วมกัน`,
        )}
        confirmText={addMutation.isPending ? t('Blocking…', 'กำลังบล็อก…') : t('Block IP', 'บล็อก IP')}
        isDanger
      />
    </section>
  )
}
