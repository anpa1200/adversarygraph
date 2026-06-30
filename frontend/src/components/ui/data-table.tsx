import type { ReactNode } from 'react';
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table';
import { useState } from 'react';
import { cn } from '@/utils/cn';

export function DataTable<TData>({
  data,
  columns,
  empty = 'No records.',
  className,
}: {
  data: TData[];
  columns: ColumnDef<TData>[];
  empty?: ReactNode;
  className?: string;
}) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <div className={cn('overflow-auto rounded border border-gray-800', className)}>
      <table className="w-full border-collapse text-left text-xs">
        <thead className="sticky top-0 z-10 bg-gray-950 text-gray-500">
          {table.getHeaderGroups().map(headerGroup => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map(header => (
                <th key={header.id} className="border-b border-gray-800 px-3 py-2 font-semibold">
                  {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map(row => (
            <tr key={row.id} className="border-b border-gray-900 hover:bg-gray-900/80">
              {row.getVisibleCells().map(cell => (
                <td key={cell.id} className="px-3 py-2 align-top text-gray-300">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
          {table.getRowModel().rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-3 py-8 text-center text-gray-500">{empty}</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
