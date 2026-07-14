import React from 'react';
import { LoadingSpinner } from './LoadingSpinner';
import { EmptyState } from './EmptyState';

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
        <EmptyState title="No data available" subtitle="There are no records to display." />
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
