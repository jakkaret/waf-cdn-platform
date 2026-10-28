import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Trash2, RefreshCw } from 'lucide-react'
import {
  getManagedStatus,
  setManagedMode,
  updateManagedToLatest,
  getTenantRules,
  getTenantRuleOptions,
  createTenantRule,
  updateTenantRule,
  deleteTenantRule,
  getDecoys,
  setDecoy,
  applyRecommendedDecoys,
  TenantRule,
  TenantRuleInput,
} from '../api/wafRules'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { LoadingSpinner } from './ui/LoadingSpinner'
import { ConfirmDialog } from './ui/ConfirmDialog'
import { probeDecoy, type DecoyProbe } from '../api/honeypot'
import { severityLabel, useT } from '../i18n'

interface Props {
  originId: string
  /** Origin Admin (creator or granted Admin). Viewers get a read-only view. */
  canEdit: boolean
}

const EMPTY_RULE: TenantRuleInput = {
  variable: 'REQUEST_URI',
  operator: '@contains ',
  message: '',
  action: 'BLOCK',
  severity: 'HIGH',
  deception_template: 'auto',
  enabled: true,
}

const errText = (e: any, fallback: string) => {
  const detail = e?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export const OriginWafRules: React.FC<Props> = ({ originId, canEdit }) => {
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [form, setForm] = useState<TenantRuleInput>(EMPTY_RULE)
  const { t, lang } = useT()

  const managedKey = ['managed-rules', originId]
  const rulesKey = ['tenant-rules', originId]

  const { data: managed, isLoading: managedLoading } = useQuery({
    queryKey: managedKey,
    queryFn: async () => (await getManagedStatus(originId)).data,
  })
  const { data: options } = useQuery({
    queryKey: ['tenant-rule-options', originId],
    queryFn: async () => (await getTenantRuleOptions(originId)).data,
  })
  const { data: rules, isLoading: rulesLoading } = useQuery({
    queryKey: rulesKey,
    queryFn: async () => (await getTenantRules(originId)).data.rules,
  })
  const decoysKey = ['tenant-decoys', originId]
  const { data: decoys } = useQuery({
    queryKey: decoysKey,
    queryFn: async () => (await getDecoys(originId)).data.decoys,
  })

  // Before a decoy goes on, ask the origin whether it already serves that
  // path (api/honeypot.py probe). Advisory: a failed or skipped probe never
  // blocks the switch, a page that answers asks for confirmation first.
  const [probing, setProbing] = useState<string | null>(null)
  const [probes, setProbes] = useState<Record<string, DecoyProbe>>({})
  const [collision, setCollision] = useState<{ key: string; label: string; status?: number } | null>(null)
  const enableDecoy = async (key: string, label: string) => {
    setProbing(key)
    let probe: DecoyProbe | null = null
    try {
      probe = await probeDecoy(originId, key)
      setProbes((p) => ({ ...p, [key]: probe! }))
    } catch {
      probe = null
    } finally {
      setProbing(null)
    }
    if (probe?.checked && probe.serves_path) setCollision({ key, label, status: probe.status })
    else decoyMutation.mutate({ key, enabled: true })
  }

  const decoyMutation = useMutation({
    mutationFn: ({ key, enabled }: { key: string; enabled: boolean }) => setDecoy(originId, key, enabled),
    onSuccess: (res, vars) => {
      queryClient.setQueryData(decoysKey, res.data.decoys)
      queryClient.invalidateQueries({ queryKey: rulesKey })
      toast.success(vars.enabled ? t('Decoy turned on', 'เปิด decoy แล้ว') : t('Decoy turned off', 'ปิด decoy แล้ว'))
    },
    onError: (e) => toast.error(errText(e, t('Failed to change decoy', 'เปลี่ยน decoy ไม่สำเร็จ'))),
  })

  const applyRecommendedMutation = useMutation({
    mutationFn: () => applyRecommendedDecoys(originId),
    onSuccess: (res) => {
      queryClient.setQueryData(decoysKey, res.data.decoys)
      queryClient.invalidateQueries({ queryKey: rulesKey })
      toast.success(t('Turned on the recommended decoys', 'เปิด decoy ที่แนะนำแล้ว'))
    },
    onError: (e) => toast.error(errText(e, t('Failed to apply recommended decoys', 'เปิด decoy ที่แนะนำไม่สำเร็จ'))),
  })

  const modeMutation = useMutation({
    mutationFn: (mode: 'auto' | 'manual') => setManagedMode(originId, mode, managed?.current_version),
    onSuccess: (res) => {
      queryClient.setQueryData(managedKey, res.data)
      toast.success(
        res.data.mode === 'auto'
          ? t('Managed rules now update automatically', 'Managed rules อัปเดตอัตโนมัติแล้ว')
          : t('Managed rules now update manually', 'Managed rules อัปเดตเองแล้ว'),
      )
    },
    onError: (e) => toast.error(errText(e, t('Failed to change mode', 'เปลี่ยนโหมดไม่สำเร็จ'))),
  })

  const updateMutation = useMutation({
    mutationFn: () => updateManagedToLatest(originId),
    onSuccess: (res) => {
      queryClient.setQueryData(managedKey, res.data)
      toast.success(t(`Updated to managed ruleset v${res.data.current_version}`, `อัปเดตเป็น managed ruleset v${res.data.current_version} แล้ว`))
    },
    onError: (e) => toast.error(errText(e, t('Update failed', 'อัปเดตไม่สำเร็จ'))),
  })

  const closeForm = () => {
    setShowForm(false)
    setEditingId(null)
    setForm(EMPTY_RULE)
  }

  const saveMutation = useMutation({
    mutationFn: () =>
      editingId === null ? createTenantRule(originId, form) : updateTenantRule(originId, editingId, form),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: rulesKey })
      toast.success(editingId === null ? t('Rule created', 'สร้างกฎแล้ว') : t('Rule updated', 'อัปเดตกฎแล้ว'))
      closeForm()
    },
    onError: (e) => toast.error(errText(e, t('Failed to save rule', 'บันทึกกฎไม่สำเร็จ'))),
  })

  const deleteMutation = useMutation({
    mutationFn: (ruleId: number) => deleteTenantRule(originId, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: rulesKey })
      toast.success(t('Rule deleted', 'ลบกฎแล้ว'))
    },
    onError: (e) => toast.error(errText(e, t('Failed to delete rule', 'ลบกฎไม่สำเร็จ'))),
  })

  const toggleMutation = useMutation({
    mutationFn: (rule: TenantRule) =>
      updateTenantRule(originId, rule.id, {
        variable: rule.variable,
        operator: rule.operator,
        message: rule.message,
        action: rule.action,
        severity: rule.severity,
        deception_template: rule.deception_template,
        enabled: !rule.enabled,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: rulesKey }),
    onError: (e) => toast.error(errText(e, t('Failed to update rule', 'อัปเดตกฎไม่สำเร็จ'))),
  })

  const startEdit = (rule: TenantRule) => {
    setEditingId(rule.id)
    setForm({
      variable: rule.variable,
      operator: rule.operator,
      message: rule.message,
      action: rule.action,
      severity: rule.severity,
      deception_template: rule.deception_template,
      enabled: rule.enabled,
    })
    setShowForm(true)
  }

  const [operatorName, ...operatorValue] = form.operator.split(' ')
  const setOperatorName = (name: string) => setForm((f) => ({ ...f, operator: `${name} ${operatorValue.join(' ')}` }))
  const setOperatorValue = (value: string) => setForm((f) => ({ ...f, operator: `${operatorName} ${value}` }))

  const inputClass = 'w-full dash-input font-mono'
  const labelClass = 'text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block'

  // Decoy-path rules show as checkboxes in their own section, not in the list.
  const customRules = (rules ?? []).filter((r) => !r.decoy)
  const recommendedCount = (decoys ?? []).filter((d) => d.recommended && !d.enabled).length

  return (
    <div className="space-y-6">
      {/* ── Managed ruleset ─────────────────────────────────────────── */}
      <section className="space-y-3">
        <div>
          <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">Managed rules</h2>
          <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
            {t(
              'Rules maintained centrally for every origin (known CVEs and exploit patterns). Nobody can edit them; the platform publishes new versions over time.',
              'กฎที่ดูแลจากส่วนกลางสำหรับทุก origin (CVE และรูปแบบการโจมตีที่รู้จัก) ไม่มีใครแก้ไขได้ แพลตฟอร์มจะออกเวอร์ชันใหม่เป็นระยะ',
            )}
          </p>
        </div>

        {managedLoading || !managed ? (
          <LoadingSpinner />
        ) : (
          <div className="dash-card p-5 space-y-4">
            <div className="flex flex-wrap items-center gap-3 font-mono text-[12px]">
              <span className="text-[var(--text-muted)]">{t('Running', 'ใช้อยู่')}</span>
              <Badge color="brand">v{managed.current_version}</Badge>
              <span className="text-[var(--text-muted)]">{t('Latest', 'ล่าสุด')}</span>
              <Badge color={managed.update_available ? 'warning' : 'success'}>v{managed.latest_version}</Badge>
              <Badge color="gray">{managed.mode === 'auto' ? t('Auto-update', 'อัปเดตอัตโนมัติ') : t('Manual updates', 'อัปเดตเอง')}</Badge>
              {canEdit && managed.update_available && (
                <Button
                  size="sm"
                  icon={<RefreshCw size={13} />}
                  onClick={() => updateMutation.mutate()}
                  isLoading={updateMutation.isPending}
                >
                  {t('Update to', 'อัปเดตเป็น')} v{managed.latest_version}
                </Button>
              )}
            </div>

            {canEdit && (
              <label className="flex items-center gap-2 text-[12px] font-mono text-[var(--text-primary)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={managed.mode === 'auto'}
                  disabled={modeMutation.isPending}
                  onChange={(e) => modeMutation.mutate(e.target.checked ? 'auto' : 'manual')}
                />
                {t('Apply new versions automatically', 'ใช้เวอร์ชันใหม่โดยอัตโนมัติ')}
                <span className="text-[var(--text-muted)]">
                  {t(
                    `(turn off to stay on v${managed.current_version} until you press Update)`,
                    `(ปิดไว้เพื่อใช้ v${managed.current_version} ต่อจนกว่าจะกดอัปเดต)`,
                  )}
                </span>
              </label>
            )}

            <div className="overflow-x-auto">
              <table className="dash-table">
                <thead>
                  <tr>
                    <th>{t('Rule', 'กฎ')}</th>
                    <th>{t('Description', 'คำอธิบาย')}</th>
                    <th>{t('Severity', 'ความรุนแรง')}</th>
                    <th>{t('Added', 'เพิ่มใน')}</th>
                    <th>{t('Status', 'สถานะ')}</th>
                  </tr>
                </thead>
                <tbody>
                  {managed.rules.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-[var(--text-muted)] font-mono text-[12px]">
                        {t('No managed rules published yet.', 'ยังไม่มี managed rules')}
                      </td>
                    </tr>
                  ) : (
                    managed.rules.map((r) => (
                      <tr key={r.id}>
                        <td className="font-mono font-bold text-orange-500">{r.id}</td>
                        <td className="text-[12px] text-[var(--text-secondary)]">{r.message}</td>
                        <td>
                          <Badge color={r.severity === 'CRITICAL' ? 'danger' : 'warning'}>{severityLabel(r.severity, lang)}</Badge>
                        </td>
                        <td className="font-mono text-[11.5px]">v{r.introduced_in}</td>
                        <td>
                          {r.retired_in !== null ? (
                            <Badge color="gray">{t('Retired in', 'เลิกใช้ใน')} v{r.retired_in}</Badge>
                          ) : r.active ? (
                            <Badge color="success">{t('Active', 'ใช้งานอยู่')}</Badge>
                          ) : (
                            <Badge color="warning">{t('Pending update', 'รออัปเดต')}</Badge>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {managed.versions.length > 0 && (
              <details className="text-[12px] font-mono">
                <summary className="cursor-pointer text-[var(--text-muted)]">{t('Version history', 'ประวัติเวอร์ชัน')}</summary>
                <ul className="mt-2 space-y-1 list-none p-0">
                  {[...managed.versions].reverse().map((v) => (
                    <li key={v.version} className="text-[var(--text-secondary)]">
                      <strong>v{v.version}</strong> · {v.published_at} · +{v.added.length} / -{v.retired.length}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        )}
      </section>

      {/* ── Decoy paths ─────────────────────────────────────────────── */}
      <section className="space-y-3">
        <div className="flex justify-between items-start gap-3">
          <div>
            <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">{t('Decoy paths', 'Path ล่อ (decoy)')}</h2>
            <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
              {t(
                "One-click honeypots for URLs bots and scanners probe on every site. When on, the path returns believable fake content instead of reaching your server, and the hit is logged. Recommendations use this origin's tech-stack tags — a path your stack really uses is warned against, not recommended.",
                'กับดัก (honeypot) แบบคลิกเดียวสำหรับ URL ที่บอทและสแกนเนอร์ชอบลองทุกเว็บ เมื่อเปิด path นั้นจะตอบเนื้อหาปลอมที่ดูสมจริงแทนการส่งไปเซิร์ฟเวอร์ของคุณ และบันทึกการเข้าถึงไว้ คำแนะนำอิงจาก tech stack tags ของ origin นี้ — path ที่ระบบของคุณใช้จริงจะได้คำเตือน ไม่ใช่คำแนะนำ',
              )}
            </p>
          </div>
          {canEdit && recommendedCount > 0 && (
            <Button
              variant="secondary"
              onClick={() => applyRecommendedMutation.mutate()}
              disabled={applyRecommendedMutation.isPending}
              isLoading={applyRecommendedMutation.isPending}
            >
              {t(`Turn on ${recommendedCount} recommended`, `เปิด ${recommendedCount} รายการที่แนะนำ`)}
            </Button>
          )}
        </div>
        {(['universal', 'stack'] as const).map((tier) => {
          const rows = (decoys ?? []).filter((d) => d.tier === tier)
          if (rows.length === 0) return null
          return (
            <div key={tier} className="dash-card p-4">
              <h3 className="text-[11px] font-bold font-mono text-[var(--text-muted)] mb-2">
                {tier === 'universal' ? t('Safe for any site', 'ปลอดภัยกับทุกเว็บ') : t('Depends on your stack', 'ขึ้นกับระบบของคุณ')}
              </h3>
              <div className="space-y-2.5">
                {rows.map((d) => (
                  <div key={d.key} className="flex items-start gap-2.5 text-[12px] font-mono">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      aria-label={d.label}
                      checked={d.enabled}
                      disabled={!canEdit || decoyMutation.isPending || probing !== null}
                      onChange={(e) =>
                        e.target.checked ? enableDecoy(d.key, d.label) : decoyMutation.mutate({ key: d.key, enabled: false })
                      }
                    />
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className={d.enabled ? 'text-[var(--text-primary)]' : 'text-[var(--text-secondary)]'}>
                          {d.label}
                        </span>
                        {d.enabled && <Badge color="warning">DECEIVE</Badge>}
                        {!d.enabled && d.recommended && <Badge color="success">{t('Recommended', 'แนะนำ')}</Badge>}
                        {!d.enabled && d.collision && <Badge color="danger">{t('Your stack uses this', 'ระบบของคุณใช้ path นี้')}</Badge>}
                      </div>
                      <p className="text-[11px] text-[var(--text-muted)] m-0 mt-0.5">{d.reason}</p>
                      {probing === d.key && (
                        <p className="text-[11px] text-[var(--text-muted)] m-0 mt-0.5">{t('Checking whether your site serves this path…', 'กำลังตรวจว่าเว็บของคุณมี path นี้จริงไหม…')}</p>
                      )}
                      {probes[d.key] && probing !== d.key && (
                        <p className={`text-[11px] m-0 mt-0.5 ${probes[d.key].serves_path ? 'text-red-600 dark:text-red-400' : 'text-[var(--text-muted)]'}`}>
                          {!probes[d.key].checked
                            ? probes[d.key].reason === 'tunnel'
                              ? t('Not checked: a tunnel origin is reached only through its agent. Make sure your site does not use this path.', 'ไม่ได้ตรวจ: origin แบบ tunnel เข้าถึงได้ผ่าน agent เท่านั้น ตรวจเองว่าเว็บไม่ได้ใช้ path นี้')
                              : t('Not checked: the origin could not be asked directly.', 'ไม่ได้ตรวจ: ถามเซิร์ฟเวอร์ต้นทางโดยตรงไม่ได้')
                            : probes[d.key].serves_path
                              ? t(`Your site answers this path (HTTP ${probes[d.key].status}).`, `เว็บของคุณตอบ path นี้ (HTTP ${probes[d.key].status})`)
                              : t('Checked: your site does not serve this path.', 'ตรวจแล้ว: เว็บของคุณไม่มี path นี้')}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )
        })}
      </section>

      <ConfirmDialog
        open={collision !== null}
        isDanger
        title={t('Your site uses this path', 'เว็บของคุณใช้ path นี้')}
        message={
          collision
            ? t(
                `Your site answered ${collision.label} with HTTP ${collision.status}, so it looks like a real page. With the decoy on, real visitors there get the fake page instead. Turn it on anyway?`,
                `เว็บของคุณตอบ ${collision.label} ด้วย HTTP ${collision.status} จึงน่าจะเป็นหน้าจริง ถ้าเปิด decoy ผู้ใช้จริงที่เข้าหน้านี้จะเจอหน้าปลอมแทน ยืนยันจะเปิดไหม`,
              )
            : ''
        }
        confirmText={t('Turn on anyway', 'เปิดต่อไป')}
        onCancel={() => setCollision(null)}
        onConfirm={() => {
          if (collision) decoyMutation.mutate({ key: collision.key, enabled: true })
          setCollision(null)
        }}
      />

      {/* ── This origin's own rules ─────────────────────────────────── */}
      <section className="space-y-3">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">{t('Custom rules', 'กฎที่กำหนดเอง')}</h2>
            <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
              {t(
                "Rules for this origin only. They apply to requests for this origin's DNS-verified domains and can never affect another origin's traffic.",
                'กฎเฉพาะ origin นี้ ใช้กับ request ของโดเมนที่ยืนยัน DNS แล้วของ origin นี้เท่านั้น และไม่มีผลกับทราฟฟิกของ origin อื่น',
              )}
            </p>
          </div>
          {canEdit && (
            <Button
              variant={showForm ? 'secondary' : 'brand'}
              onClick={() => (showForm ? closeForm() : setShowForm(true))}
            >
              {showForm ? t('Cancel', 'ยกเลิก') : t('+ Add rule', '+ เพิ่มกฎ')}
            </Button>
          )}
        </div>

        {canEdit && showForm && options && (
          <div className="dash-card p-5 border-l-2 border-l-orange-500 bg-orange-500/[0.02]">
            <h3 className="text-[13.5px] font-bold text-orange-500 font-mono mb-4">
              {editingId === null ? t('New rule', 'กฎใหม่') : t(`Edit rule ${editingId}`, `แก้ไขกฎ ${editingId}`)}
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[12px]">
              <div>
                <label className={labelClass}>{t('Look at', 'ตรวจที่')}</label>
                <select
                  className={inputClass}
                  value={form.variable}
                  onChange={(e) => setForm((f) => ({ ...f, variable: e.target.value }))}
                >
                  {Object.entries(options.variables).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className={labelClass}>{t('Match type', 'วิธีจับคู่')}</label>
                <select className={inputClass} value={operatorName} onChange={(e) => setOperatorName(e.target.value)}>
                  {options.operators.map((op) => (
                    <option key={op} value={op}>
                      {op}
                    </option>
                  ))}
                </select>
              </div>
              <div className="md:col-span-2">
                <label className={labelClass}>{t('Value', 'ค่า')}</label>
                <input
                  className={inputClass}
                  placeholder={t('e.g. /wp-admin', 'เช่น /wp-admin')}
                  value={operatorValue.join(' ')}
                  onChange={(e) => setOperatorValue(e.target.value)}
                />
              </div>
              <div>
                <label className={labelClass}>{t('Action', 'การดำเนินการ')}</label>
                <select
                  className={inputClass}
                  value={form.action}
                  onChange={(e) => setForm((f) => ({ ...f, action: e.target.value as TenantRuleInput['action'] }))}
                >
                  {options.actions.map((a) => (
                    <option key={a} value={a}>
                      {a}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className={labelClass}>{t('Severity', 'ความรุนแรง')}</label>
                <select
                  className={inputClass}
                  value={form.severity}
                  onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value as TenantRuleInput['severity'] }))}
                >
                  {options.severities.map((s) => (
                    <option key={s} value={s}>
                      {severityLabel(s, lang)}
                    </option>
                  ))}
                </select>
              </div>
              <div className="md:col-span-2">
                <label className={labelClass}>{t('Message (shown in logs)', 'ข้อความ (แสดงใน log)')}</label>
                <input
                  className={inputClass}
                  placeholder={t('e.g. Block wp-admin probes', 'เช่น บล็อกการสแกน wp-admin')}
                  value={form.message}
                  onChange={(e) => setForm((f) => ({ ...f, message: e.target.value }))}
                />
              </div>
            </div>
            <div className="flex justify-end mt-4">
              <Button
                variant="brand"
                onClick={() => saveMutation.mutate()}
                disabled={!operatorValue.join(' ').trim() || !form.message.trim() || saveMutation.isPending}
                isLoading={saveMutation.isPending}
              >
                {t('Save rule', 'บันทึกกฎ')}
              </Button>
            </div>
          </div>
        )}

        <div className="dash-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="dash-table">
              <thead>
                <tr>
                  <th>{t('Rule', 'กฎ')}</th>
                  <th>{t('Condition', 'เงื่อนไข')}</th>
                  <th>{t('Action', 'การดำเนินการ')}</th>
                  <th>{t('Message', 'ข้อความ')}</th>
                  <th>{t('On', 'เปิด')}</th>
                  {canEdit && <th className="text-right">{t('Manage', 'จัดการ')}</th>}
                </tr>
              </thead>
              <tbody>
                {rulesLoading ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-[var(--text-muted)] font-mono text-[12px]">
                      {t('Loading rules...', 'กำลังโหลดกฎ...')}
                    </td>
                  </tr>
                ) : customRules.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-[var(--text-muted)] font-mono text-[12px]">
                      {t('No custom rules for this origin.', 'origin นี้ยังไม่มีกฎที่กำหนดเอง')}
                    </td>
                  </tr>
                ) : (
                  customRules.map((rule) => (
                    <tr key={rule.id}>
                      <td className="font-mono font-bold text-orange-500">{rule.id}</td>
                      <td className="font-mono text-[11.5px] max-w-[260px] truncate">
                        {rule.variable} {rule.operator}
                      </td>
                      <td>
                        <Badge color={rule.action === 'BLOCK' ? 'danger' : 'warning'}>{rule.action}</Badge>
                      </td>
                      <td className="text-[12px] text-[var(--text-secondary)]">{rule.message}</td>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={t(`Rule ${rule.id} enabled`, `เปิดกฎ ${rule.id}`)}
                          checked={rule.enabled}
                          disabled={!canEdit || toggleMutation.isPending}
                          onChange={() => toggleMutation.mutate(rule)}
                        />
                      </td>
                      {canEdit && (
                        <td className="text-right whitespace-nowrap">
                          <button
                            onClick={() => startEdit(rule)}
                            className="text-orange-500 hover:text-orange-400 font-mono text-[11px] font-semibold cursor-pointer mr-3"
                          >
                            {t('Edit', 'แก้ไข')}
                          </button>
                          <button
                            onClick={() => deleteMutation.mutate(rule.id)}
                            disabled={deleteMutation.isPending}
                            className="text-red-500 hover:text-red-400 cursor-pointer"
                            aria-label={t(`Delete rule ${rule.id}`, `ลบกฎ ${rule.id}`)}
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
        </div>
      </section>
    </div>
  )
}
