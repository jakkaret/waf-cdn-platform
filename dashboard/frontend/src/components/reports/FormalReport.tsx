import React, { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import type { Postmortem } from '../../types'
import { ReportText } from '../ai/ReportText'
import { ReportChart, ChartLegend } from './ReportChart'
import { blockedShare, honeypotRows, rangeFacts, reportFileBase, reportNumber, reportSeries } from '../../lib/reportExport'
import { longDateTh, splitBkk } from '../../lib/reportRange'
import { bkkDateKey, formatBkkTime, formatBkkDateTime } from '../../lib/time'

// The incident report as a formal A4 document. It is printed through the
// browser (Save as PDF), which renders Thai correctly; the page itself is
// hidden on paper by the .print-root rules in index.css.

const PRINT_COLORS = { requests: '#b8c2cf', alerts: '#b42318', axis: '#6b7280', grid: '#e5e7eb', text: '#4b5563' }

const thDateTime = (bkkText: string): string => {
  const p = splitBkk(bkkText)
  return p ? `${longDateTh(p.date)} เวลา ${p.time} น.` : bkkText || '—'
}

const thStamp = (raw: string | Date): string => {
  const day = bkkDateKey(raw)
  return day ? `${longDateTh(day)} เวลา ${formatBkkTime(raw)} น.` : '—'
}

const n = (v: number | undefined | null) => (v ?? 0).toLocaleString('en-US')

export const FormalReport: React.FC<{ pm: Postmortem; printedAt: Date }> = ({ pm, printedAt }) => {
  const facts = rangeFacts(pm)
  const series = reportSeries(pm)
  const types = pm.stats?.top_attack_types || []
  const events = pm.audit_events || []
  const hpRows = honeypotRows(pm)
  const typesTotal = types.reduce((a, t) => a + (t.count || 0), 0)

  return (
    <article className="pr-doc">
      <header className="pr-head">
        <div className="pr-org">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#111827" strokeWidth="1.8" strokeLinejoin="round" aria-hidden="true">
            <path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
          <div>
            <b>IT KKU · WAF &amp; CDN Platform</b>
            <span>ระบบป้องกันเว็บแอปพลิเคชันและเครือข่ายส่งเนื้อหา</span>
          </div>
        </div>
        <div className="pr-no">
          <span>เลขที่รายงาน</span>
          <b>{reportNumber(pm)}</b>
        </div>
      </header>

      <h1 className="pr-title">รายงานสรุปเหตุการณ์ด้านความปลอดภัย</h1>
      <p className="pr-subtitle">Security Incident Report</p>

      <table className="pr-kv">
        <tbody>
          <tr><th>เว็บไซต์</th><td>{pm.origin_label || '—'}</td></tr>
          <tr><th>ช่วงเวลาที่ตรวจสอบ</th><td>{thDateTime(pm.start_time)} ถึง {thDateTime(pm.end_time)}</td></tr>
          <tr>
            <th>ระยะเวลา</th>
            <td>{facts.days !== null ? `${facts.days} วัน` : '—'}{facts.duration ? ` (รวม ${facts.duration})` : ''}</td>
          </tr>
          <tr><th>จัดทำโดย</th><td>{pm.created_by_username || '—'}</td></tr>
          <tr><th>วันที่จัดทำรายงาน</th><td>{thStamp(pm.created_at)}</td></tr>
          <tr><th>วันที่พิมพ์เอกสาร</th><td>{thStamp(printedAt)}</td></tr>
        </tbody>
      </table>

      <h2 className="pr-h2">1. ภาพรวมสถานการณ์</h2>
      <table className="pr-table">
        <thead><tr><th>ตัวชี้วัด</th><th className="pr-r">ค่า</th></tr></thead>
        <tbody>
          <tr><td>คำขอทั้งหมดที่ผ่านระบบ</td><td className="pr-r">{n(pm.stats?.total_requests)}</td></tr>
          <tr><td>คำขอที่ถูกบล็อกหรือแจ้งเตือน</td><td className="pr-r">{n(pm.stats?.total_alerts)}</td></tr>
          <tr><td>สัดส่วนที่ถูกบล็อก</td><td className="pr-r">{blockedShare(pm)}</td></tr>
          <tr><td>การเปลี่ยนแปลงในระบบช่วงเวลาเดียวกัน</td><td className="pr-r">{n(events.length)} รายการ</td></tr>
        </tbody>
      </table>

      <h2 className="pr-h2">2. บทสรุปผู้บริหาร</h2>
      <p className="pr-note">ร่างโดย AI จากข้อมูลในรายงานนี้ ผู้จัดทำควรตรวจทานก่อนเผยแพร่{pm.ai_narrative_degraded ? ' (บทสรุปอาจไม่ครบถ้วน)' : ''}</p>
      {pm.ai_narrative ? (
        <ReportText text={pm.ai_narrative} className="pr-narrative" />
      ) : (
        <p className="pr-muted">ไม่มีบทสรุปจาก AI สำหรับรายงานนี้ โปรดอ้างอิงตัวเลขในหัวข้อ 1, 3 และ 4</p>
      )}

      <h2 className="pr-h2">3. ประเภทการโจมตีที่พบมากที่สุด</h2>
      {types.length ? (
        <table className="pr-table">
          <thead><tr><th className="pr-r" style={{ width: 48 }}>ลำดับ</th><th>ประเภท</th><th className="pr-r">จำนวน</th><th className="pr-r">สัดส่วน</th></tr></thead>
          <tbody>
            {types.map((t, i) => (
              <tr key={`${t.type}-${i}`}>
                <td className="pr-r">{i + 1}</td>
                <td>{t.type}</td>
                <td className="pr-r">{n(t.count)}</td>
                <td className="pr-r">{typesTotal ? `${((t.count / typesTotal) * 100).toFixed(1)}%` : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="pr-muted">ไม่พบประเภทการโจมตีในช่วงเวลานี้</p>
      )}

      <h2 className="pr-h2">4. ปริมาณคำขอราย{series.unit === 'day' ? 'วัน' : 'ชั่วโมง'}</h2>
      {series.points.length ? (
        <div className="pr-chart">
          <ReportChart points={series.points} unit={series.unit} colors={PRINT_COLORS} height={190} />
          <ChartLegend colors={PRINT_COLORS} />
        </div>
      ) : (
        <p className="pr-muted">ไม่มีคำขอในช่วงเวลานี้</p>
      )}

      <h2 className="pr-h2">5. กับดัก (Honeypot)</h2>
      {!hpRows ? (
        <p className="pr-muted">รายงานนี้จัดทำก่อนระบบเริ่มเก็บข้อมูล honeypot</p>
      ) : !hpRows[0].value ? (
        <p className="pr-muted">ไม่มีผู้เข้ากับดักในช่วงเวลานี้</p>
      ) : (
        <>
          <table className="pr-table">
            <thead><tr><th>รายการ</th><th className="pr-r">จำนวน</th></tr></thead>
            <tbody>
              {hpRows.map((r) => (
                <tr key={r.label}><td>{r.label}</td><td className="pr-r">{n(r.value)}</td></tr>
              ))}
            </tbody>
          </table>
          <p className="pr-muted">ทุกคำขอที่เข้ากับดักได้รับเนื้อหาปลอม ไม่ถึงเว็บจริง จำนวนแต่ละขั้นนับ session ที่ไปถึงขั้นนั้นหรือไกลกว่า</p>
        </>
      )}

      <h2 className="pr-h2">6. การเปลี่ยนแปลงในระบบระหว่างช่วงเวลา</h2>
      {events.length ? (
        <table className="pr-table">
          <thead><tr><th style={{ width: 150 }}>เวลา</th><th style={{ width: 120 }}>ผู้ดำเนินการ</th><th>รายการ</th></tr></thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.event_id}>
                <td style={{ whiteSpace: 'nowrap' }}>{formatBkkDateTime(ev.timestamp, { seconds: false })}</td>
                <td>{ev.actor_username || '—'}</td>
                <td>{ev.summary || ev.action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="pr-muted">ไม่มีการเปลี่ยนแปลงการตั้งค่าในช่วงเวลานี้</p>
      )}

      <h2 className="pr-h2">7. การรับรองรายงาน</h2>
      <div className="pr-signs">
        {['ผู้จัดทำรายงาน', 'ผู้ตรวจสอบ', 'ผู้อนุมัติ'].map((role) => (
          <div key={role} className="pr-sign">
            <p>ลงชื่อ ..............................................</p>
            <p>( .............................................. )</p>
            <p>ตำแหน่ง ..........................................</p>
            <p>วันที่ ........../........../..........</p>
            <b>{role}</b>
          </div>
        ))}
      </div>

      <footer className="pr-foot">
        ตัวเลขในรายงานนี้นับจาก log ของระบบ WAF โดยตรง ณ เวลาที่สร้างรายงาน ส่วนบทสรุปผู้บริหารร่างโดย AI · {reportNumber(pm)}
      </footer>
    </article>
  )
}

// Print one report: render it into a print-only layer, open the browser's
// print dialog (where Save as PDF lives), then remove the layer.
export function usePrintReport(): { print: (pm: Postmortem) => void; layer: React.ReactNode } {
  const [job, setJob] = useState<{ pm: Postmortem; at: Date } | null>(null)

  useEffect(() => {
    if (!job) return
    const prevTitle = document.title
    // Browsers suggest the document title as the PDF file name.
    document.title = reportFileBase(job.pm)
    const done = () => setJob(null)
    window.addEventListener('afterprint', done, { once: true })
    const t = window.setTimeout(() => window.print(), 80)
    return () => {
      window.clearTimeout(t)
      window.removeEventListener('afterprint', done)
      document.title = prevTitle
    }
  }, [job])

  const layer = job
    ? createPortal(
        <div className="print-root" aria-hidden="true">
          <FormalReport pm={job.pm} printedAt={job.at} />
        </div>,
        document.body,
      )
    : null

  return { print: (pm) => setJob({ pm, at: new Date() }), layer }
}

export default FormalReport
