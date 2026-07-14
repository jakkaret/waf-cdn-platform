import React from 'react';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  subtitle?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ icon, title, subtitle }) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center h-full">
      {icon && (
        <div className="w-16 h-16 mb-4 rounded-full bg-bg-surface2 flex items-center justify-center text-text-muted">
          {icon}
        </div>
      )}
      <h3 className="text-lg font-medium text-text-primary mb-2">{title}</h3>
      {subtitle && <p className="text-sm text-text-muted max-w-sm">{subtitle}</p>}
    </div>
  );
};
