import React from 'react';
import { LoadingSpinner } from './LoadingSpinner';
import { EmptyState } from './EmptyState';
import { useT } from '../../i18n';

interface Column<T> {
  key: string;
  header: string;
  render?: (item: T) => React.ReactNode;
}

interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (item: T) => void;
  loading?: boolean;
}

export function Table<T extends Record<string, any>>({ columns, data, onRowClick, loading }: TableProps<T>) {
  const { t } = useT();
  if (loading) {
    return (
      <div className="py-12 flex justify-center">
        <LoadingSpinner />
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="py-8 border-t border-bg-border">
        <EmptyState title={t('No data available', 'ไม่มีข้อมูล')} subtitle={t('There are no records to display.', 'ยังไม่มีรายการให้แสดง')} />
      </div>
    );
  }

  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full text-left text-sm text-text-primary">
        <thead className="bg-bg-surface2/50 text-text-muted border-b border-bg-border">
          <tr>
            {columns.map((col) => (
              <th key={col.key} className="px-6 py-4 font-medium">{col.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((item, i) => (
            <tr 
              key={i} 
              onClick={() => onRowClick?.(item)}
              className={`border-b border-bg-border/50 hover:bg-bg-surface2/30 transition-colors ${onRowClick ? 'cursor-pointer' : ''}`}
            >
              {columns.map((col) => (
                <td key={col.key} className="px-6 py-4 whitespace-nowrap">
                  {col.render ? col.render(item) : item[col.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
