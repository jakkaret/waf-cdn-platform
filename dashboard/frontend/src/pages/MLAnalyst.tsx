import React from 'react'
import { TopBar } from '../components/layout/TopBar'
import { MLInsights } from '../components/ml/MLInsights'

// AI Security Analyst: ML Insights, the Gen 3 scores of the origin's real
// traffic. The page where a request was pasted in by hand is gone
// (2026-10-27): an Owner or Editor proposes a rule straight from a flagged
// request in the list instead.

export const MLAnalyst: React.FC = () => (
  <div className="space-y-6 animate-fade-in">
    <TopBar
      title="AI Security Analyst"
      subtitle="ML Insights: คะแนนจากโมเดล Gen 3 ของ traffic จริงทุก request เจ้าของเว็บเสนอกฎจาก request ที่ถูกตั้งข้อสังเกตได้จากรายการด้านล่าง"
    />
    <MLInsights />
  </div>
)

export default MLAnalyst
