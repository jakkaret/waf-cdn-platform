import React from 'react'
import { TopBar } from '../components/layout/TopBar'
import { MLInsights } from '../components/ml/MLInsights'
import { useT } from '../i18n'

// AI Security Analyst: ML Insights, the Gen 3 scores of the origin's real
// traffic. The page where a request was pasted in by hand is gone
// (2026-10-27): an Owner or Editor proposes a rule straight from a flagged
// request in the list instead.

export const MLAnalyst: React.FC = () => {
  const { t } = useT()
  return (
  <div className="space-y-6 animate-fade-in">
    <TopBar
      scope
      title="ML insights"
      subtitle={t(
        'Anomaly scores from the ML model for every request your sites receive. A score is an estimate, not a confirmed attack. Owners and Editors can propose a rule from a flagged request; it waits in Rule proposals for approval.',
        'คะแนนความผิดปกติจากโมเดล ML ของทุก request ที่เข้าเว็บของคุณ คะแนนเป็นค่าประมาณ ไม่ใช่การยืนยันว่าเป็นการโจมตี Owner และ Editor เสนอกฎจาก request ที่ถูกตั้งธงได้ ข้อเสนอจะรออนุมัติในหน้ากฎที่รอตรวจ',
      )}
    />
    <MLInsights />
  </div>
  )
}

export default MLAnalyst
