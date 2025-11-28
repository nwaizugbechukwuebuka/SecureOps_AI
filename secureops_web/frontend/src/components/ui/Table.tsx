import * as React from 'react';
import { cn } from '../../utils/helpers';

interface TableProps {
  columns: string[];
  data: Array<Record<string, any>>;
  className?: string;
}

export const Table: React.FC<TableProps> = ({ columns, data, className }) => (
  <table className={cn('min-w-full bg-white rounded shadow', className)}>
    <thead>
      <tr>
        {columns.map((col) => (
          <th key={col} className="px-4 py-2 text-left font-semibold text-gray-700">{col}</th>
        ))}
      </tr>
    </thead>
    <tbody>
      {data.map((row, idx) => (
        <tr key={idx} className="border-t">
          {columns.map((col) => (
            <td key={col} className="px-4 py-2">{row[col]}</td>
          ))}
        </tr>
      ))}
    </tbody>
  </table>
);
