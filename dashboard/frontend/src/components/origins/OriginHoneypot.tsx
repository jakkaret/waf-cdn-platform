import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Ban, Download, FileText, Link2, Sparkles, Upload, KeyRound, X } from 'lucide-react'
import {
  blockHoneypotSession,
  getHoneypotSession,
  getHoneypotSessions,
  getHoneypotStory,
  getHoneypotSummary,
  type HoneypotStage,
  type HoneypotStep,
} from '../../api/honeypot'
import { STAGES, STAGE_BAR, STAGE_META, STAGE_TONE, formatSpan, iocCsv, stageLabel } from '../../lib/honeypot'
import { DURATIONS } from '../../lib/siteAccess'
import { BKK_LABEL, bkkDateKey, formatBkkDateTime } from '../../lib/time'
import { Button } from '../ui/Button'
import { LoadingSpinner } from '../ui/LoadingSpinner'
import { Modal } from '../ui/Modal'
import { useT } from '../../i18n'

// The origin's Honeypot tab: what visitors did inside this site's decoys.
// Every request shown here got a fake answer and never reached the site.
// Paths, user agents and the AI story come from attacker input: shown as
// text only.

const WINDOWS = [1, 7, 30, 90]

const errText = (e: any, fallback: string) => {
  const detail = e?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

const StagePill: React.FC<{ stage: HoneypotStage }> = ({ stage }) => {
  const { lang } = useT()
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11.5px] font-medium whitespace-nowrap ${STAGE_TONE[stage]}`}>
      {stageLabel(stage, lang)}
    </span>
  )
}

export const OriginHoneypot: React.FC<{ originId: string; canEdit: boolean }> = ({ originId, canEdit }) => {
  const { t, lang } = useT()
  const [days, setDays] = useState(7)
  const [selected, setSelected] = useState<string | null>(null)

  const summary = useQuery({
    queryKey: ['honeypot-summary', originId, days],
    queryFn: () => getHoneypotSummary(originId, days),
    enabled: canEdit,
  })
  const list = useQuery({
    queryKey: ['honeypot-sessions', originId, days],
    queryFn: () => getHoneypotSessions(originId, days),
    enabled: canEdit,
  })

  const exportIoc = () => {
    const sessions = list.data?.sessions ?? []
    const blob = new Blob([iocCsv(sessions)], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `honeypot-ioc_${bkkDateKey()}_${days}d.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  if (!canEdit) {
    return (
      <p role="note" className="m-0 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] px-4 py-3 text-[13px] text-[var(--text-secondary)]">
        {t(
          "Honeypot sessions hold attackers' IPs and what they sent, so only the Owner and Editors of this origin can open them.",
          'session ของ honeypot มี IP และข้อมูลที่ผู้โจมตีส่งมา จึงเปิดดูได้เฉพาะ Owner และ Editor ของ origin นี้',
        )}
      </p>
    )
  }

  const s = summary.data
  const maxDay = Math.max(1, ...(s?.per_day ?? []).map((d) => d.sessions))

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-[16px] font-semibold text-[var(--text-primary)] m-0">Honeypot</h2>
          <p className="text-[13px] text-[var(--text-muted)] m-0 mt-0.5 max-w-[80ch]">
            {t(
              'Visitors who hit a decoy path get a fake answer instead of your site. Each session is one visitor (same IP and browser) with no gap over 30 minutes: what they looked for, what fake secrets they took and whether they came back to use them.',
              'ผู้ที่เข้า path กับดักจะได้คำตอบปลอมแทนเว็บจริง หนึ่ง session คือผู้มาเยือนหนึ่งราย (IP และ browser เดียวกัน) ที่ไม่หายไปเกิน 30 นาที ดูได้ว่าเขาหาอะไร ได้ข้อมูลลับปลอมอะไรไป และกลับมาใช้หรือไม่',
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div role="group" aria-label={t('Time window', 'ช่วงเวลา')} className="inline-flex rounded-lg border border-[var(--bg-border)] overflow-hidden">
            {WINDOWS.map((d) => (
              <button
                key={d}
                type="button"
                aria-pressed={days === d}
                onClick={() => {
                  setDays(d)
                  setSelected(null)
                }}
                className={`px-3 h-8 text-[12.5px] cursor-pointer ${days === d ? 'bg-[var(--accent)] text-white font-semibold' : 'text-[var(--text-secondary)] hover:bg-[var(--bg-surface-hover)]'}`}
              >
                {d === 1 ? t('24 h', '24 ชม.') : t(`${d} days`, `${d} วัน`)}
              </button>
            ))}
          </div>
          <Button variant="outline" size="sm" icon={<Download size={14} />} onClick={exportIoc} disabled={!list.data?.sessions.length}>
            {t('IOC CSV', 'IOC CSV')}
          </Button>
        </div>
      </div>

      {summary.isLoading ? (
        <LoadingSpinner />
      ) : summary.isError || !s ? (
        <p className="m-0 text-[13px] text-red-600 dark:text-red-400">{t('Could not load the honeypot summary. Reload to try again.', 'โหลดสรุป honeypot ไม่สำเร็จ รีโหลดเพื่อลองใหม่')}</p>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="dash-card p-4">
            <div className="grid grid-cols-3 gap-2">
              {[
                { v: s.sessions, l: t('Sessions', 'Session') },
                { v: s.unique_ips, l: t('IPs', 'IP') },
                { v: s.events, l: t('Requests', 'คำขอ') },
              ].map((c) => (
                <div key={c.l}>
                  <div className="text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{c.v.toLocaleString('en-US')}</div>
                  <div className="text-[12px] text-[var(--text-muted)]">{c.l}</div>
                </div>
              ))}
            </div>
            <div className="mt-4 flex items-end gap-[3px] h-16" aria-label={t('Sessions per day', 'Session ต่อวัน')} role="img">
              {s.per_day.map((d) => (
                <div
                  key={d.day}
                  title={`${d.day}: ${d.sessions}`}
                  className="flex-1 rounded-sm bg-[var(--accent)] min-h-[2px]"
                  style={{ height: `${Math.max(3, (d.sessions / maxDay) * 100)}%`, opacity: d.sessions ? 1 : 0.25 }}
                />
              ))}
            </div>
            <div className="mt-1 text-[11px] text-[var(--text-muted)]">{t('Sessions per day (Bangkok time)', 'Session ต่อวัน (เวลาไทย)')}</div>
          </div>

          <div className="dash-card p-4">
            <h3 className="m-0 text-[13px] font-semibold text-[var(--text-primary)]">{t('How far they got', 'ไปได้ไกลแค่ไหน')}</h3>
            <ul className="m-0 mt-2 p-0 list-none space-y-1.5">
              {STAGES.map((st) => {
                const n = s.reached[st] ?? 0
                const pct = s.sessions ? (n / s.sessions) * 100 : 0
                return (
                  <li key={st} className="text-[12.5px]">
                    <div className="flex justify-between gap-2">
                      <span className="text-[var(--text-secondary)]">
                        {stageLabel(st, lang)} <span className="font-mono text-[11px] text-[var(--text-muted)]">{STAGE_META[st].attack}</span>
                      </span>
                      <span className="tabular-nums font-medium text-[var(--text-primary)]">{n}</span>
                    </div>
                    <div className="h-1.5 rounded bg-[var(--bg-surface-active)] overflow-hidden">
                      <div className={`h-full ${STAGE_BAR[st]}`} style={{ width: `${pct}%` }} />
                    </div>
                  </li>
                )
              })}
            </ul>
          </div>

          <div className="dash-card p-4">
            <h3 className="m-0 text-[13px] font-semibold text-[var(--text-primary)]">{t('Tools seen', 'เครื่องมือที่พบ')}</h3>
            {s.tools.length ? (
              <ul className="m-0 mt-2 p-0 list-none space-y-1 text-[12.5px]">
                {s.tools.map((tool) => (
                  <li key={tool.tool} className="flex justify-between gap-2">
                    <span className="text-[var(--text-secondary)] truncate">{tool.tool}</span>
                    <span className="tabular-nums text-[var(--text-primary)]">{tool.sessions}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="m-0 mt-2 text-[12.5px] text-[var(--text-muted)]">{t('Nothing yet', 'ยังไม่มี')}</p>
            )}
          </div>
        </div>
      )}

      {list.isLoading ? null : list.isError ? (
        <p className="m-0 text-[13px] text-red-600 dark:text-red-400">{t('Could not load the sessions. Reload to try again.', 'โหลดรายการ session ไม่สำเร็จ รีโหลดเพื่อลองใหม่')}</p>
      ) : !list.data?.sessions.length ? (
        <div className="dash-card p-6 text-center text-[13px] text-[var(--text-muted)]">
          {t(
            'No one has entered a decoy in this window. Turn decoy paths on under Protection, WAF policies.',
            'ยังไม่มีใครเข้ากับดักในช่วงนี้ เปิด path กับดักได้ที่ การป้องกัน > นโยบาย WAF',
          )}
        </div>
      ) : (
        <div className="dash-card overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>{t(`Last seen (${BKK_LABEL})`, 'ล่าสุด (เวลาไทย)')}</th>
                <th>{t('Tool', 'เครื่องมือ')}</th>
                <th>IP</th>
                <th>{t('Got as far as', 'ไปถึงขั้น')}</th>
                <th className="text-right">{t('Requests', 'คำขอ')}</th>
                <th>{t('Length', 'ระยะเวลา')}</th>
                <th><span className="sr-only">{t('Details', 'รายละเอียด')}</span></th>
              </tr>
            </thead>
            <tbody>
              {list.data.sessions.map((row) => (
                <tr key={row.id} className={selected === row.id ? 'bg-[var(--bg-surface-hover)]' : ''}>
                  <td className="whitespace-nowrap">{formatBkkDateTime(row.last_seen, { seconds: false })}</td>
                  <td className="max-w-[16ch] truncate" title={row.user_agent}>{row.tool}</td>
                  <td className="font-mono text-[12px]">
                    {row.ips[0]}
                    {row.ips.length > 1 && <span className="text-[var(--text-muted)]"> +{row.ips.length - 1}</span>}
                  </td>
                  <td>
                    <div className="flex flex-wrap items-center gap-1">
                      <StagePill stage={row.max_stage} />
                      {row.linked_from.length > 0 && (
                        <span title={t('Used a fake secret another session took', 'ใช้ข้อมูลลับปลอมที่อีก session ได้ไป')} className="inline-flex text-red-600 dark:text-red-400">
                          <Link2 size={14} aria-label={t('linked', 'เชื่อมโยง')} />
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="text-right tabular-nums">{row.events}</td>
                  <td className="whitespace-nowrap">{formatSpan(row.duration_seconds, lang)}</td>
                  <td>
                    <Button variant="ghost" size="xs" onClick={() => setSelected(selected === row.id ? null : row.id)} aria-expanded={selected === row.id}>
                      {selected === row.id ? t('Close', 'ปิด') : t('Timeline', 'ไทม์ไลน์')}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {list.data.total > list.data.sessions.length && (
            <p className="m-0 px-4 py-2 text-[12px] text-[var(--text-muted)]">
              {t(`Showing the latest ${list.data.sessions.length} of ${list.data.total}.`, `แสดง ${list.data.sessions.length} รายการล่าสุดจาก ${list.data.total}`)}
            </p>
          )}
        </div>
      )}

      {selected && <SessionDetail originId={originId} sid={selected} days={Math.max(days, 30)} onClose={() => setSelected(null)} onPick={setSelected} />}
    </section>
  )
}

const SessionDetail: React.FC<{ originId: string; sid: string; days: number; onClose: () => void; onPick: (sid: string) => void }> = ({
  originId,
  sid,
  days,
  onClose,
  onPick,
}) => {
  const { t, lang } = useT()
  const queryClient = useQueryClient()
  const [blocking, setBlocking] = useState(false)
  const [hours, setHours] = useState<number | null>(24)
  const detail = useQuery({ queryKey: ['honeypot-session', originId, sid, days], queryFn: () => getHoneypotSession(originId, sid, days) })
  const story = useMutation({
    mutationFn: () => getHoneypotStory(originId, sid, days),
    onError: (e) => toast.error(errText(e, t('The AI summary failed. Try again later.', 'สรุปด้วย AI ไม่สำเร็จ ลองใหม่ภายหลัง'))),
  })
  const block = useMutation({
    mutationFn: () => blockHoneypotSession(originId, sid, hours, days),
    onSuccess: (r) => {
      queryClient.invalidateQueries({ queryKey: ['site-ip-rules', originId] })
      if (r.added.length) toast.success(t(`Blocked ${r.added.length} IP on this origin`, `บล็อก ${r.added.length} IP ใน origin นี้แล้ว`))
      if (r.skipped.length) toast(t(`${r.skipped.length} skipped: ${r.skipped[0].reason}`, `ข้าม ${r.skipped.length} รายการ: ${r.skipped[0].reason}`))
    },
    onError: (e) => toast.error(errText(e, t('Could not block. Nothing was changed.', 'บล็อกไม่สำเร็จ ยังไม่มีอะไรเปลี่ยน'))),
    onSettled: () => setBlocking(false),
  })

  if (detail.isLoading) return <LoadingSpinner />
  if (detail.isError || !detail.data)
    return <p className="m-0 text-[13px] text-red-600 dark:text-red-400">{t('Could not load this session.', 'โหลด session นี้ไม่สำเร็จ')}</p>
  const s = detail.data

  return (
    <div className="dash-card p-5 space-y-4" aria-label={t('Session timeline', 'ไทม์ไลน์ของ session')}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="m-0 text-[15px] font-semibold text-[var(--text-primary)]">{s.tool}</h3>
            {s.stages.map((st) => (
              <StagePill key={st} stage={st} />
            ))}
          </div>
          <p className="m-0 text-[12.5px] text-[var(--text-muted)]">
            {formatBkkDateTime(s.first_seen, { seconds: false })} – {formatBkkDateTime(s.last_seen, { seconds: false })} · {formatSpan(s.duration_seconds, lang)} ·{' '}
            {t(`${s.events} requests`, `${s.events} คำขอ`)} · edge {s.edge_nodes.join(', ')}
          </p>
          <p className="m-0 font-mono text-[12px] text-[var(--text-secondary)] break-all">{s.ips.join(', ')}</p>
          <p className="m-0 font-mono text-[11.5px] text-[var(--text-muted)] break-all">{s.user_agent || '—'}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" icon={<Sparkles size={14} />} onClick={() => story.mutate()} isLoading={story.isPending}>
            {t('Explain with AI', 'สรุปด้วย AI')}
          </Button>
          <Button variant="brand" size="sm" icon={<Ban size={14} />} onClick={() => setBlocking(true)}>
            {t(`Block ${s.ips.length} IP`, `บล็อก ${s.ips.length} IP`)}
          </Button>
          <Button variant="ghost" size="sm" icon={<X size={14} />} onClick={onClose} aria-label={t('Close', 'ปิด')} />
        </div>
      </div>

      {(s.login_attempts > 0 || s.uploads.length > 0 || s.tokens_issued.length > 0 || s.linked_from.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[12.5px]">
          {s.login_attempts > 0 && (
            <Fact icon={<KeyRound size={14} />}>
              {t(
                `${s.login_attempts} login attempts, ${s.distinct_passwords} different passwords (${s.common_passwords} from common-password lists). Passwords are not stored.`,
                `พยายามล็อกอิน ${s.login_attempts} ครั้ง รหัสผ่านต่างกัน ${s.distinct_passwords} แบบ (${s.common_passwords} ครั้งเป็นรหัสยอดนิยม) ระบบไม่เก็บรหัสผ่าน`,
              )}
            </Fact>
          )}
          {s.uploads.map((u) => (
            <Fact key={u.sha256} icon={<Upload size={14} />}>
              {t('Uploaded', 'อัปโหลด')} <span className="font-mono">{u.name}</span> ({u.size.toLocaleString('en-US')} bytes) · SHA-256{' '}
              <span className="font-mono break-all">{u.sha256}</span>
            </Fact>
          ))}
          {s.tokens_issued.length > 0 && (
            <Fact icon={<FileText size={14} />}>
              {t('Fake secrets handed out:', 'ข้อมูลลับปลอมที่แจกไป:')} <span className="font-mono">{s.tokens_issued.join(', ')}</span>
              {s.tokens_replayed.length > 0 && (
                <>
                  {' · '}
                  {t('used:', 'ถูกนำมาใช้:')} <span className="font-mono">{s.tokens_replayed.join(', ')}</span>
                </>
              )}
            </Fact>
          )}
          {s.linked_from.length > 0 && (
            <Fact icon={<Link2 size={14} />}>
              {t('Used a fake secret taken in', 'ใช้ข้อมูลลับปลอมที่ได้ไปใน')}{' '}
              {s.linked_from.map((l, i) => (
                <React.Fragment key={l}>
                  {i > 0 && ', '}
                  <button type="button" className="underline cursor-pointer text-[var(--accent)]" onClick={() => onPick(l)}>
                    {t('this session', 'session นี้')}
                  </button>
                </React.Fragment>
              ))}
            </Fact>
          )}
        </div>
      )}

      {story.data && (
        <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] p-3 text-[13px]">
          <div className="mb-1 text-[11.5px] font-semibold text-[var(--text-muted)]">{t('AI summary (check before acting on it)', 'สรุปโดย AI (ตรวจทานก่อนนำไปใช้)')}</div>
          {story.data.story ? (
            <div className="whitespace-pre-wrap text-[var(--text-primary)]">{story.data.story}</div>
          ) : (
            <div className="text-[var(--text-muted)]">{t('The AI did not answer. The timeline below is complete.', 'AI ไม่ตอบ ไทม์ไลน์ด้านล่างยังครบถ้วน')}</div>
          )}
        </div>
      )}

      <ol className="m-0 p-0 list-none border-l border-[var(--bg-border)] ml-2 space-y-3">
        {s.timeline.map((step, i) => (
          <TimelineStep key={`${step.request_id}-${i}`} step={step} />
        ))}
      </ol>

      <Modal open={blocking} onClose={() => setBlocking(false)} title={t('Block this session', 'บล็อก session นี้')}>
        <div className="space-y-3 text-[13px]">
          <p className="m-0">
            {t(
              `Block ${s.ips.length} IP on this origin's domains. Real visitors behind the same address will get 403 too.`,
              `บล็อก ${s.ips.length} IP บนโดเมนของ origin นี้ ผู้ใช้จริงที่ใช้ IP เดียวกันจะได้ 403 ด้วย`,
            )}
          </p>
          <p className="m-0 font-mono text-[12px] break-all">{s.ips.join(', ')}</p>
          <label className="block">
            <span className="text-[12px] font-medium text-[var(--text-secondary)]">{t('Duration', 'ระยะเวลา')}</span>
            <select className="mt-1 w-full dash-input" value={hours ?? ''} onChange={(e) => setHours(e.target.value ? Number(e.target.value) : null)}>
              {DURATIONS.map((d) => (
                <option key={d.label} value={d.hours ?? ''}>
                  {t(d.label, d.labelTh)}
                </option>
              ))}
            </select>
          </label>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setBlocking(false)}>
              {t('Cancel', 'ยกเลิก')}
            </Button>
            <Button variant="danger" onClick={() => block.mutate()} isLoading={block.isPending}>
              {t('Block', 'บล็อก')}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

const Fact: React.FC<{ icon: React.ReactNode; children: React.ReactNode }> = ({ icon, children }) => (
  <div className="flex items-start gap-2 rounded-lg bg-[var(--bg-surface)] border border-[var(--bg-border)] px-3 py-2 text-[var(--text-secondary)]">
    <span className="mt-0.5 shrink-0 text-[var(--text-muted)]">{icon}</span>
    <span className="min-w-0">{children}</span>
  </div>
)

const TimelineStep: React.FC<{ step: HoneypotStep }> = ({ step }) => {
  const { t, lang } = useT()
  const [open, setOpen] = useState(false)
  const meta = STAGE_META[step.stage]
  return (
    <li className="relative pl-4">
      <span className="absolute -left-[5px] top-1.5 h-2.5 w-2.5 rounded-full bg-[var(--accent)]" aria-hidden />
      <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
        <span className="tabular-nums text-[var(--text-muted)]">{formatBkkDateTime(step.time)}</span>
        <StagePill stage={step.stage} />
        <span className="font-mono text-[11px] text-[var(--text-muted)]" title={step.attack_name}>{step.attack_id}</span>
        {step.client_ip && <span className="font-mono text-[11px] text-[var(--text-muted)]">{step.client_ip}</span>}
      </div>
      <div className="mt-0.5 font-mono text-[12.5px] text-[var(--text-primary)] break-all">
        <span className="font-semibold">{step.method}</span> {step.path}
        {step.query && <span className="text-[var(--text-muted)]">?{step.query}</span>}
      </div>
      <div className="text-[12px] text-[var(--text-muted)]">
        {lang === 'th' ? meta.descTh : meta.desc}
        {step.category && ` · ${step.category}`}
        {step.delay_ms > 0 && ` · ${t(`held ${step.delay_ms} ms`, `หน่วง ${step.delay_ms} ms`)}`}
      </div>
      {step.login && (
        <div className="text-[12px] text-[var(--text-secondary)]">
          {t('Login as', 'ล็อกอินเป็น')} <span className="font-mono">{step.login.user || '—'}</span> ·{' '}
          {t(`password ${step.login.password_length} characters`, `รหัสผ่าน ${step.login.password_length} ตัวอักษร`)}
          {step.login.common_password && ` · ${t('a common password', 'รหัสยอดนิยม')}`}
        </div>
      )}
      {step.upload && (
        <div className="text-[12px] text-[var(--text-secondary)]">
          {t('File', 'ไฟล์')} <span className="font-mono">{step.upload.name}</span> ({step.upload.size.toLocaleString('en-US')} bytes, {step.upload.type || '?'})
        </div>
      )}
      {step.tokens_issued.length > 0 && (
        <div className="text-[12px] text-amber-700 dark:text-amber-300">
          {t('Handed out fake:', 'แจกของปลอม:')} <span className="font-mono">{step.tokens_issued.join(', ')}</span>
        </div>
      )}
      {step.token_replayed && (
        <div className="text-[12px] text-red-700 dark:text-red-300">
          {t('Came back with fake:', 'ใช้ของปลอม:')} <span className="font-mono">{step.token_replayed}</span>
        </div>
      )}
      {step.body_sample && (
        <div className="mt-1">
          <button type="button" className="text-[12px] underline cursor-pointer text-[var(--text-secondary)]" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
            {open ? t('Hide what was sent', 'ซ่อนข้อมูลที่ส่งมา') : t('Show what was sent', 'ดูข้อมูลที่ส่งมา')}
          </button>
          {open && (
            <pre className="mt-1 max-h-48 overflow-auto rounded bg-[var(--bg-surface-active)] p-2 text-[11.5px] whitespace-pre-wrap break-all">{step.body_sample}</pre>
          )}
        </div>
      )}
    </li>
  )
}
