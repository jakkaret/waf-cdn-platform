import React from 'react'

// Platform name, in one place. The two-tone colours are the ones the old
// "IT KKU" wordmark used, so the logo image still matches.
export const BRAND_NAME = 'AegisWAF CDN'

export const BrandName: React.FC<{ className?: string }> = ({ className = '' }) => (
  <span className={className}>
    <span className="text-[#a34830] dark:text-[#d0674a]">Aegis</span>
    <span className="text-[var(--text-primary)]">WAF</span>{' '}
    <span className="text-[#6b6b6c] dark:text-[#a3a3a4]">CDN</span>
  </span>
)

export default BrandName
