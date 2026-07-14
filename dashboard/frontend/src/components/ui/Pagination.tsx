import React from 'react';

interface PaginationProps {
  page: number;
  totalPages: number;
  onChange: (page: number) => void;
}

export const Pagination: React.FC<PaginationProps> = ({ page, totalPages, onChange }) => {
  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-between px-6 py-4 border-t border-bg-border bg-bg-surface">
      <div className="text-sm text-text-muted">
        Showing page <span className="font-medium text-text-primary">{page}</span> of <span className="font-medium text-text-primary">{totalPages}</span>
      </div>
      <div className="flex gap-2">
        <button
          onClick={() => onChange(page - 1)}
          disabled={page === 1}
          className="px-3 py-1 text-sm bg-bg-surface2 text-text-primary rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-bg-border transition-colors"
        >
          Previous
        </button>
        <button
          onClick={() => onChange(page + 1)}
          disabled={page === totalPages}
          className="px-3 py-1 text-sm bg-bg-surface2 text-text-primary rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-bg-border transition-colors"
        >
          Next
        </button>
      </div>
    </div>
  );
};
