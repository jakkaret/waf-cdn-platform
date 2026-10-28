import React, { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { AlertTriangle, CheckCircle2, Clock } from 'lucide-react'
import { getMlProtection, MlMode, MlProtectionInput, previewMlProtection, saveMlProtection } from '../api/mlProtection'
import { bandError, bandRange, bands, BLOCK_RANGE, CHALLENGE_RANGE, isDirty, share, SUGGESTED } from '../lib/mlProtection'
import { formatBkkDateTime } from '../lib/time'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { LoadingSpinner } from './ui/LoadingSpinner'
import { useT } from '../i18n'

interface Props {
  originId: string
  /** Owner or Editor. Viewers get a read-only view. */
  canEdit: boolean
}

const errText = (e: any, fallback: string) => {
  const detail = e?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

const BAND_STYLE: Record<string, string> = {
  pass: 'bg-[var(--bg-border)] text-[var(--text-secondary)]',
  challenge: 'bg-[var(--warning)] text-white',
  block: 'bg-[var(--danger)] text-white',
}

// The form's values, settled for 400 ms, so typing a score does not query on every key.
function useSettled<T>(value: T, ms = 400): T {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), ms)
    return () => clearTimeout(timer)
  }, [value, ms])
  return settled
}

export const OriginMlProtection: React.FC<Props> = ({ originId, canEdit }) => {
  const queryClient = useQueryClient()
  const key = ['ml-protection', originId]
  const { data: saved, isLoading } = useQuery({ queryKey: key, queryFn: () => getMlProtection(originId) })

  const [form, setForm] = useState<MlProtectionInput | null>(null)
  const [ack, setAck] = useState(false)
  const { t, lang } = useT()
  useEffect(() => {
    if (saved && form === null) {
      setForm({ mode: saved.mode, challenge_score: saved.challenge_score, block_score: saved.block_score })
    }
  }, [saved, form])

  const challenge = form?.challenge_score ?? null
  const block = form?.block_score ?? SUGGESTED.block
  const error = form ? bandError(challenge, block, lang) : null
  const settled = useSettled({ challenge, block })
  const settledOk = bandError(settled.challenge, settled.block) === null

  const { data: preview, isFetching: previewLoading, isError: previewError } = useQuery({
    queryKey: ['ml-protection-preview', originId, settled.challenge, settled.block],
    queryFn: () => previewMlProtection(originId, settled.challenge, settled.block),
    enabled: !!form && settledOk,
    staleTime: 60_000,
  })

  const saveMutation = useMutation({
    mutationFn: (body: MlProtectionInput) => saveMlProtection(originId, body),
    onSuccess: (res) => {
      queryClient.setQueryData(key, res)
      setForm({ mode: res.mode, challenge_score: res.challenge_score, block_score: res.block_score })
      setAck(false)
      toast.success(
        res.mode === 'enforce'
          ? t('ML protection is enforcing', 'การป้องกันด้วย ML บังคับใช้แล้ว')
          : t('ML protection is back to log only', 'การป้องกันด้วย ML กลับเป็นบันทึก log อย่างเดียวแล้ว'),
      )
    },
    onError: (e) => toast.error(errText(e, t('Failed to save ML protection', 'บันทึกการป้องกันด้วย ML ไม่สำเร็จ'))),
  })

  if (isLoading || !saved || !form) return <LoadingSpinner />

  const dirty = isDirty(saved, form)
  const turningOn = saved.mode === 'log' && form.mode === 'enforce'
  const canSave = canEdit && dirty && !error && (!turningOn || ack)
  const labelClass = 'text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block'
  const setMode = (mode: MlMode) => setForm((f) => (f ? { ...f, mode } : f))
  const bandLabel = (key: string) =>
    key === 'challenge' ? t('Challenge', 'ทดสอบ') : key === 'block' ? t('Block', 'บล็อก') : t('Allowed', 'ผ่าน')

  return (
    <section className="space-y-4">
      <div>
        <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">{t('ML protection', 'การป้องกันด้วย ML')}</h2>
        <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5 max-w-3xl">
          {t(
            'The Gen 3 model scores every request to this origin from 0 to 100, body included, after ModSecurity has let it through. In log mode the score is only recorded (see ML Insights). In enforce mode a high score can send the visitor to a challenge or block the request. If the model is unavailable, requests go through.',
            'โมเดล Gen 3 ให้คะแนนทุก request ที่มายัง origin นี้ตั้งแต่ 0 ถึง 100 รวมถึง body หลังจาก ModSecurity ปล่อยผ่านแล้ว ในโหมดบันทึก log คะแนนจะถูกบันทึกไว้เท่านั้น (ดูที่ ML insights) ในโหมดบังคับใช้ คะแนนสูงอาจส่งผู้เข้าชมไปทำด่านทดสอบหรือบล็อก request ถ้าโมเดลใช้งานไม่ได้ request จะผ่านไปตามปกติ',
          )}
        </p>
      </div>

      <div className="dash-card p-5 space-y-5 text-[12.5px]">
        <div className="flex flex-wrap items-center gap-3">
          <span className={labelClass + ' !mb-0'}>{t('Now', 'ตอนนี้')}</span>
          <Badge color={saved.mode === 'enforce' ? 'danger' : 'gray'}>
            {saved.mode === 'enforce' ? t('Enforce', 'บังคับใช้') : t('Log only', 'บันทึก log อย่างเดียว')}
          </Badge>
          {saved.applied ? (
            <span className="flex items-center gap-1 text-[var(--text-secondary)]">
              <CheckCircle2 size={14} className="text-[var(--success)]" aria-hidden="true" /> {t('Live on the WAF', 'ใช้งานบน WAF แล้ว')}
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[var(--text-secondary)]">
              <Clock size={14} className="text-[var(--warning)]" aria-hidden="true" /> {t('Being applied (within a minute)', 'กำลังนำไปใช้ (ภายในหนึ่งนาที)')}
            </span>
          )}
          {saved.updated_at && (
            <span className="text-[var(--text-muted)]">
              {t('Changed', 'เปลี่ยนเมื่อ')} {formatBkkDateTime(saved.updated_at, { seconds: false })}
              {saved.updated_by ? t(` by ${saved.updated_by}`, ` โดย ${saved.updated_by}`) : ''}
            </span>
          )}
        </div>
        {saved.map_error && (
          <p className="m-0 flex items-start gap-1.5 text-[var(--danger)]">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
            {t('The WAF refused the last change and kept the previous one. It is retried every minute.', 'WAF ไม่รับการเปลี่ยนครั้งล่าสุดและใช้ค่าเดิมต่อ ระบบจะลองใหม่ทุกนาที')}
          </p>
        )}

        <fieldset className="m-0 p-0 border-0" disabled={!canEdit}>
          <legend className={labelClass}>{t('Mode', 'โหมด')}</legend>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {([
              ['log', t('Log only (default)', 'บันทึก log อย่างเดียว (ค่าเริ่มต้น)'), t('Score and record. Nothing is blocked by ML.', 'ให้คะแนนและบันทึกไว้ ML ไม่บล็อกอะไร')],
              ['enforce', t('Enforce', 'บังคับใช้'), t('Challenge or block requests by score, with the bands below.', 'ทดสอบหรือบล็อก request ตามคะแนน ตามช่วงด้านล่าง')],
            ] as const).map(([mode, title, text]) => (
              <label
                key={mode}
                className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${
                  form.mode === mode ? 'border-orange-500 bg-orange-500/5' : 'border-[var(--bg-border)]'
                }`}
              >
                <input
                  type="radio"
                  name={`ml-mode-${originId}`}
                  className="mt-0.5"
                  checked={form.mode === mode}
                  onChange={() => setMode(mode)}
                />
                <span>
                  <span className="block font-semibold text-[var(--text-primary)]">{title}</span>
                  <span className="block text-[var(--text-muted)]">{text}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <fieldset className="m-0 p-0 border-0 space-y-3" disabled={!canEdit}>
          <legend className={labelClass}>{t('Score bands', 'ช่วงคะแนน')}</legend>
          <div className="flex flex-wrap items-end gap-4">
            <label className="flex items-center gap-2 text-[var(--text-secondary)]">
              <input
                type="checkbox"
                checked={challenge !== null}
                onChange={(e) =>
                  setForm((f) => (f ? { ...f, challenge_score: e.target.checked ? Math.min(SUGGESTED.challenge, f.block_score - 1) : null } : f))
                }
              />
              {t('Challenge before blocking', 'ทดสอบก่อนบล็อก')}
            </label>
            <div>
              <label className={labelClass} htmlFor={`ml-challenge-${originId}`}>{t('Challenge from', 'ทดสอบตั้งแต่')}</label>
              <input
                id={`ml-challenge-${originId}`}
                type="number"
                className="dash-input font-mono w-24"
                min={CHALLENGE_RANGE[0]}
                max={CHALLENGE_RANGE[1]}
                disabled={challenge === null}
                value={challenge ?? ''}
                onChange={(e) => setForm((f) => (f ? { ...f, challenge_score: e.target.value === '' ? CHALLENGE_RANGE[0] : Number(e.target.value) } : f))}
              />
            </div>
            <div>
              <label className={labelClass} htmlFor={`ml-block-${originId}`}>{t('Block from', 'บล็อกตั้งแต่')}</label>
              <input
                id={`ml-block-${originId}`}
                type="number"
                className="dash-input font-mono w-24"
                min={BLOCK_RANGE[0]}
                max={BLOCK_RANGE[1]}
                value={Number.isFinite(block) ? block : ''}
                onChange={(e) => setForm((f) => (f ? { ...f, block_score: Number(e.target.value) } : f))}
              />
            </div>
            <span className="text-[var(--text-muted)]">
              {t(
                `Suggested: challenge ${SUGGESTED.challenge}, block ${SUGGESTED.block}`,
                `ค่าแนะนำ: ทดสอบ ${SUGGESTED.challenge}, บล็อก ${SUGGESTED.block}`,
              )}
            </span>
          </div>
          {error ? (
            <p className="m-0 text-[var(--danger)]">{error}</p>
          ) : (
            <div>
              <div className="flex h-7 w-full overflow-hidden rounded-md" role="img" aria-label={t('What each score does', 'แต่ละคะแนนทำอะไร')}>
                {bands(challenge, block).map((b) => (
                  <div
                    key={b.key}
                    className={`flex items-center justify-center text-[11px] font-semibold ${BAND_STYLE[b.key]}`}
                    style={{ width: `${Math.max(b.to - b.from, 4)}%` }}
                    title={`${bandLabel(b.key)}: ${bandRange(b)}`}
                  >
                    {b.to - b.from >= 8 ? `${bandLabel(b.key)} ${bandRange(b)}` : bandRange(b)}
                  </div>
                ))}
              </div>
              <p className="m-0 mt-1.5 text-[var(--text-muted)]">
                {challenge !== null
                  ? t(
                      `A visitor who already passed the challenge on this site is not challenged again. A score of ${block} or more is blocked whatever the visitor holds.`,
                      `ผู้เข้าชมที่ผ่านด่านทดสอบของเว็บนี้แล้วจะไม่ถูกทดสอบซ้ำ คะแนนตั้งแต่ ${block} ขึ้นไปจะถูกบล็อกเสมอ`,
                    )
                  : t(
                      `Requests scoring ${block} or more are blocked; everything below goes through.`,
                      `request ที่ได้คะแนนตั้งแต่ ${block} ขึ้นไปจะถูกบล็อก ที่ต่ำกว่านั้นผ่านได้`,
                    )}
              </p>
            </div>
          )}
        </fieldset>

        <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] p-4">
          <p className="m-0 font-semibold text-[var(--text-primary)]">{t('What these bands would have done in the last 7 days', 'ถ้าใช้ช่วงคะแนนนี้ใน 7 วันที่ผ่านมาจะเกิดอะไรขึ้น')}</p>
          {error ? (
            <p className="m-0 mt-1 text-[var(--text-muted)]">{t('Fix the scores to see the preview.', 'แก้คะแนนให้ถูกต้องเพื่อดูตัวอย่าง')}</p>
          ) : previewLoading && !preview ? (
            <p className="m-0 mt-1 text-[var(--text-muted)]">{t('Counting…', 'กำลังนับ…')}</p>
          ) : previewError ? (
            <p className="m-0 mt-1 text-[var(--text-muted)]">{t('The analytics store is not answering right now. Try again shortly.', 'ระบบเก็บข้อมูลวิเคราะห์ยังไม่ตอบ ลองใหม่อีกสักครู่')}</p>
          ) : preview && preview.total === 0 ? (
            <p className="m-0 mt-1 text-[var(--text-muted)]">{t('No scored requests for this origin yet.', 'origin นี้ยังไม่มี request ที่ถูกให้คะแนน')}</p>
          ) : preview ? (
            <>
              <div className="mt-2 flex flex-wrap gap-6">
                <div>
                  <p className="m-0 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{preview.would_block.toLocaleString()}</p>
                  <p className="m-0 text-[var(--text-muted)]">{t('blocked', 'ถูกบล็อก')} ({share(preview.would_block, preview.total)})</p>
                </div>
                {challenge !== null && (
                  <div>
                    <p className="m-0 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{preview.would_challenge.toLocaleString()}</p>
                    <p className="m-0 text-[var(--text-muted)]">{t('sent to the challenge', 'ถูกส่งไปทำด่านทดสอบ')} ({share(preview.would_challenge, preview.total)})</p>
                  </div>
                )}
                <div>
                  <p className="m-0 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{preview.total.toLocaleString()}</p>
                  <p className="m-0 text-[var(--text-muted)]">
                    {t('scored requests', 'request ที่ถูกให้คะแนน')}
                    {preview.since
                      ? t(
                          ` since ${formatBkkDateTime(new Date(preview.since * 1000).toISOString(), { seconds: false })}`,
                          ` ตั้งแต่ ${formatBkkDateTime(new Date(preview.since * 1000).toISOString(), { seconds: false })}`,
                        )
                      : ''}
                  </p>
                </div>
              </div>
              {preview.examples.length > 0 && (
                <div className="mt-3">
                  <p className="m-0 mb-1 text-[var(--text-muted)]">{t('Newest requests that would have been blocked:', 'request ล่าสุดที่จะถูกบล็อก:')}</p>
                  <ul className="m-0 p-0 list-none space-y-1 font-mono text-[11.5px]">
                    {preview.examples.map((x, i) => (
                      <li key={`${x.timestamp}-${i}`} className="flex gap-3 text-[var(--text-secondary)]">
                        <span className="tabular-nums text-[var(--danger)]">{(x.score * 100).toFixed(1)}</span>
                        <span className="break-all">{x.method} {x.host}{x.path}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <p className="m-0 mt-2 text-[var(--text-muted)]">
                {t(
                  'Counted from requests ModSecurity let through. Check the examples on ML Insights before you enforce: anything a real visitor sends there would be stopped.',
                  'นับจาก request ที่ ModSecurity ปล่อยผ่าน ตรวจตัวอย่างที่ ML insights ก่อนบังคับใช้ เพราะ request จริงของผู้เข้าชมที่ตรงกันจะถูกหยุดด้วย',
                )}
              </p>
            </>
          ) : null}
        </div>

        {canEdit && (
          <div className="flex flex-wrap items-center gap-3">
            {turningOn && (
              <label className="flex items-center gap-2 text-[var(--text-secondary)]">
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                {t('I understand requests at or above these scores will really be challenged or blocked.', 'ฉันเข้าใจว่า request ที่ได้คะแนนตั้งแต่ค่านี้ขึ้นไปจะถูกทดสอบหรือบล็อกจริง')}
              </label>
            )}
            <Button disabled={!canSave} isLoading={saveMutation.isPending} onClick={() => form && saveMutation.mutate(form)}>
              {t('Save', 'บันทึก')}
            </Button>
            {dirty && (
              <button
                type="button"
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
                onClick={() => {
                  setForm({ mode: saved.mode, challenge_score: saved.challenge_score, block_score: saved.block_score })
                  setAck(false)
                }}
              >
                {t('Discard changes', 'ยกเลิกการแก้ไข')}
              </button>
            )}
          </div>
        )}

        <div className="text-[var(--text-muted)]">
          <p className="m-0">
            {t('Applies to:', 'ใช้กับ:')}{' '}
            {saved.hosts.length ? saved.hosts.join(', ') : t('no verified domain or tunnel host yet', 'ยังไม่มีโดเมนที่ยืนยันแล้วหรือ host ของ tunnel')}
          </p>
          <p className="m-0 mt-1">
            {t(
              'Not covered: static-looking paths (.css, .js, .json, images, fonts), which go through ModSecurity only. A body over 64 KB is scored without its body.',
              'ไม่ครอบคลุม: path ที่เป็นไฟล์ static (.css, .js, .json, รูปภาพ, ฟอนต์) ซึ่งผ่านแค่ ModSecurity และ body ที่ใหญ่กว่า 64 KB จะให้คะแนนโดยไม่รวม body'
            )}
          </p>
        </div>
      </div>
    </section>
  )
}
