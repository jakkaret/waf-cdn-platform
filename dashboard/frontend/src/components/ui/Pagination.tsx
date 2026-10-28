import React from 'react';
import { useT } from '../../i18n';

interface PaginationProps {
  page: number;
  totalPages: number;
  onChange: (page: number) => void;
}

export const Pagination: React.FC<PaginationProps> = ({ page, totalPages, onChange }) => {
  const { t } = useT();
  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-between px-6 py-4 border-t border-bg-border bg-bg-surface">
      <div className="text-sm text-text-muted">
        {t('Showing page', 'หน้า')} <span className="font-medium text-text-primary">{page}</span> {t('of', 'จาก')} <span className="font-medium text-text-primary">{totalPages}</span>
      </div>
      <div className="flex gap-2">
        <button
          onClick={() => onChange(page - 1)}
          disabled={page === 1}
          className="px-3 py-1 text-sm bg-bg-surface2 text-text-primary rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-bg-border transition-colors"
        >
          {t('Previous', 'ก่อนหน้า')}
        </button>
        <button
          onClick={() => onChange(page + 1)}
          disabled={page === totalPages}
          className="px-3 py-1 text-sm bg-bg-surface2 text-text-primary rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-bg-border transition-colors"
        >
          {t('Next', 'ถัดไป')}
        </button>
      </div>
    </div>
  );
};
