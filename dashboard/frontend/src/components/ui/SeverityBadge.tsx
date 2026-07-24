import React from 'react';
import { Severity } from '../../types';

interface SeverityBadgeProps {
  level: Severity | string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ level }) => {
  const upperLevel = level?.toUpperCase() || 'UNKNOWN';

  let colors = 'bg-bg-surface2 text-text-muted'; // Default/Unknown

  if (upperLevel === 'CRITICAL') {
    colors = 'bg-[#fee]/20 text-[#fc8181] border border-[#fc8181]/30';
  } else if (upperLevel === 'HIGH') {
    colors = 'bg-[#fef5e7]/10 text-[#f6ad55] border border-[#f6ad55]/30';
  } else if (upperLevel === 'MEDIUM') {
    colors = 'bg-[#fefce8]/10 text-[#f6e05e] border border-[#f6e05e]/30';
  } else if (upperLevel === 'LOW') {
    colors = 'bg-[#e6fffa]/10 text-[#76e4f7] border border-[#76e4f7]/30';
  }

  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${colors}`}>
      {upperLevel}
    </span>
  );
};
