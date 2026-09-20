import React from 'react'
import { FlaskConical } from 'lucide-react'

/**
 * Every /concepts page must render this at the top -- reviewed as a hard
 * constraint before building any concept mockup tonight (overnight
 * session, advisor call): this session spent hours deleting hardcoded
 * fake data (CDN.tsx's "14ms avg", OriginDetail.tsx's "ACTIVE" SSL
 * status) from real, live-data pages. A concept mockup with sample data
 * is the same shape of bug if it ever ends up looking like a real page.
 * This component, and never importing a concept component into a real
 * page, is what keeps the two apart.
 */
export const ConceptBanner: React.FC<{ title: string }> = ({ title }) => (
  <div className="rounded-lg border-2 border-dashed border-purple-400/50 bg-purple-500/5 p-3 flex items-center gap-2.5 mb-5">
    <FlaskConical size={16} className="text-purple-500 shrink-0" />
    <div>
      <div className="font-mono font-bold text-[12px] text-purple-600 dark:text-purple-400">
        CONCEPT -- ไม่ใช่ข้อมูลจริง
      </div>
      <div className="font-mono text-[10.5px] text-[var(--text-muted)]">
        {title}: ตัวอย่าง UI + ข้อมูลสมมติ เพื่อให้เห็นภาพก่อนตัดสินใจสร้างจริง
      </div>
    </div>
  </div>
)
