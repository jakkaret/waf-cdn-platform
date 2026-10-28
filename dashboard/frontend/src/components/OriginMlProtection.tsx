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
    const t = setTimeout(() => setSettled(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return settled
}

export const OriginMlProtection: React.FC<Props> = ({ originId, canEdit }) => {
  const queryClient = useQueryClient()
  const key = ['ml-protection', originId]
  const { data: saved, isLoading } = useQuery({ queryKey: key, queryFn: () => getMlProtection(originId) })

  const [form, setForm] = useState<MlProtectionInput | null>(null)
  const [ack, setAck] = useState(false)
  useEffect(() => {
    if (saved && form === null) {
      setForm({ mode: saved.mode, challenge_score: saved.challenge_score, block_score: saved.block_score })
    }
  }, [saved, form])

  const challenge = form?.challenge_score ?? null
  const block = form?.block_score ?? SUGGESTED.block
  const error = form ? bandError(challenge, block) : null
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
      toast.success(res.mode === 'enforce' ? 'ML protection is enforcing' : 'ML protection is back to log only')
    },
    onError: (e) => toast.error(errText(e, 'Failed to save ML protection')),
  })

  if (isLoading || !saved || !form) return <LoadingSpinner />

  const dirty = isDirty(saved, form)
  const turningOn = saved.mode === 'log' && form.mode === 'enforce'
  const canSave = canEdit && dirty && !error && (!turningOn || ack)
  const labelClass = 'text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block'
  const setMode = (mode: MlMode) => setForm((f) => (f ? { ...f, mode } : f))

  return (
    <section className="space-y-4">
      <div>
        <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">ML Protection</h2>
        <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5 max-w-3xl">
          The Gen 3 model scores every request to this origin from 0 to 100, body included, after ModSecurity has let
          it through. In log mode the score is only recorded (see ML Insights). In enforce mode a high score can send
          the visitor to a challenge or block the request. If the model is unavailable, requests go through.
        </p>
      </div>

      <div className="dash-card p-5 space-y-5 text-[12.5px]">
        <div className="flex flex-wrap items-center gap-3">
          <span className={labelClass + ' !mb-0'}>Now</span>
          <Badge color={saved.mode === 'enforce' ? 'danger' : 'gray'}>
            {saved.mode === 'enforce' ? 'Enforce' : 'Log only'}
          </Badge>
          {saved.applied ? (
            <span className="flex items-center gap-1 text-[var(--text-secondary)]">
              <CheckCircle2 size={14} className="text-[var(--success)]" aria-hidden="true" /> Live on the WAF
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[var(--text-secondary)]">
              <Clock size={14} className="text-[var(--warning)]" aria-hidden="true" /> Being applied (within a minute)
            </span>
          )}
          {saved.updated_at && (
            <span className="text-[var(--text-muted)]">
              Changed {formatBkkDateTime(saved.updated_at, { seconds: false })}
              {saved.updated_by ? ` by ${saved.updated_by}` : ''}
            </span>
          )}
        </div>
        {saved.map_error && (
          <p className="m-0 flex items-start gap-1.5 text-[var(--danger)]">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
            The WAF refused the last change and kept the previous one. It is retried every minute.
          </p>
        )}

        <fieldset className="m-0 p-0 border-0" disabled={!canEdit}>
          <legend className={labelClass}>Mode</legend>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {([
              ['log', 'Log only (default)', 'Score and record. Nothing is blocked by ML.'],
              ['enforce', 'Enforce', 'Challenge or block requests by score, with the bands below.'],
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
          <legend className={labelClass}>Score bands</legend>
          <div className="flex flex-wrap items-end gap-4">
            <label className="flex items-center gap-2 text-[var(--text-secondary)]">
              <input
                type="checkbox"
                checked={challenge !== null}
                onChange={(e) =>
                  setForm((f) => (f ? { ...f, challenge_score: e.target.checked ? Math.min(SUGGESTED.challenge, f.block_score - 1) : null } : f))
                }
              />
              Challenge before blocking
            </label>
            <div>
              <label className={labelClass} htmlFor={`ml-challenge-${originId}`}>Challenge from</label>
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
              <label className={labelClass} htmlFor={`ml-block-${originId}`}>Block from</label>
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
            <span className="text-[var(--text-muted)]">Suggested: challenge {SUGGESTED.challenge}, block {SUGGESTED.block}</span>
          </div>
          {error ? (
            <p className="m-0 text-[var(--danger)]">{error}</p>
          ) : (
            <div>
              <div className="flex h-7 w-full overflow-hidden rounded-md" role="img" aria-label="What each score does">
                {bands(challenge, block).map((b) => (
                  <div
                    key={b.key}
                    className={`flex items-center justify-center text-[11px] font-semibold ${BAND_STYLE[b.key]}`}
                    style={{ width: `${Math.max(b.to - b.from, 4)}%` }}
                    title={`${b.label}: ${bandRange(b)}`}
                  >
                    {b.to - b.from >= 8 ? `${b.label} ${bandRange(b)}` : bandRange(b)}
                  </div>
                ))}
              </div>
              <p className="m-0 mt-1.5 text-[var(--text-muted)]">
                {challenge !== null
                  ? `A visitor who already passed the challenge on this site is not challenged again. A score of ${block} or more is blocked whatever the visitor holds.`
                  : `Requests scoring ${block} or more are blocked; everything below goes through.`}
              </p>
            </div>
          )}
        </fieldset>

        <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] p-4">
          <p className="m-0 font-semibold text-[var(--text-primary)]">What these bands would have done in the last 7 days</p>
          {error ? (
            <p className="m-0 mt-1 text-[var(--text-muted)]">Fix the scores to see the preview.</p>
          ) : previewLoading && !preview ? (
            <p className="m-0 mt-1 text-[var(--text-muted)]">Counting…</p>
          ) : previewError ? (
            <p className="m-0 mt-1 text-[var(--text-muted)]">The analytics store is not answering right now. Try again shortly.</p>
          ) : preview && preview.total === 0 ? (
            <p className="m-0 mt-1 text-[var(--text-muted)]">No scored requests for this origin yet.</p>
          ) : preview ? (
            <>
              <div className="mt-2 flex flex-wrap gap-6">
                <div>
                  <p className="m-0 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{preview.would_block.toLocaleString()}</p>
                  <p className="m-0 text-[var(--text-muted)]">blocked ({share(preview.would_block, preview.total)})</p>
                </div>
                {challenge !== null && (
                  <div>
                    <p className="m-0 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{preview.would_challenge.toLocaleString()}</p>
                    <p className="m-0 text-[var(--text-muted)]">sent to the challenge ({share(preview.would_challenge, preview.total)})</p>
                  </div>
                )}
                <div>
                  <p className="m-0 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{preview.total.toLocaleString()}</p>
                  <p className="m-0 text-[var(--text-muted)]">
                    scored requests{preview.since ? ` since ${formatBkkDateTime(new Date(preview.since * 1000).toISOString(), { seconds: false })}` : ''}
                  </p>
                </div>
              </div>
              {preview.examples.length > 0 && (
                <div className="mt-3">
                  <p className="m-0 mb-1 text-[var(--text-muted)]">Newest requests that would have been blocked:</p>
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
                Counted from requests ModSecurity let through. Check the examples on ML Insights before you enforce:
                anything a real visitor sends there would be stopped.
              </p>
            </>
          ) : null}
        </div>

        {canEdit && (
          <div className="flex flex-wrap items-center gap-3">
            {turningOn && (
              <label className="flex items-center gap-2 text-[var(--text-secondary)]">
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                I understand requests at or above these scores will really be challenged or blocked.
              </label>
            )}
            <Button disabled={!canSave} isLoading={saveMutation.isPending} onClick={() => form && saveMutation.mutate(form)}>
              Save
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
                Discard changes
              </button>
            )}
          </div>
        )}

        <div className="text-[var(--text-muted)]">
          <p className="m-0">
            Applies to: {saved.hosts.length ? saved.hosts.join(', ') : 'no verified domain or tunnel host yet'}
          </p>
          <p className="m-0 mt-1">
            Not covered: static-looking paths (.css, .js, .json, images, fonts), which go through ModSecurity only. A
            body over 64 KB is scored without its body.
          </p>
        </div>
      </div>
    </section>
  )
}
