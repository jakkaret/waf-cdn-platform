import React from 'react';

interface StatusBadgeProps {
  code: number | string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ code }) => {
  const statusStr = String(code);
  let colors = 'bg-bg-surface2 text-text-muted';

  if (statusStr.startsWith('2')) {
    colors = 'bg-[#e6f9f0]/10 text-[#68d391] border border-[#68d391]/30';
  } else if (statusStr === '403') {
    colors = 'bg-[#fff4e5]/10 text-[#f6ad55] border border-[#f6ad55]/30';
  } else if (statusStr.startsWith('4')) {
    colors = 'bg-[#fff4e5]/10 text-[#f6ad55] border border-[#f6ad55]/30';
  } else if (statusStr.startsWith('5')) {
    colors = 'bg-[#fff5f5]/10 text-[#fc8181] border border-[#fc8181]/30';
  }

  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-mono font-medium ${colors}`}>
      {code}
    </span>
  );
};
