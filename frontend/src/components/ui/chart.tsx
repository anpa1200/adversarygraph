import type { ReactNode } from 'react';
import { ResponsiveContainer } from 'recharts';
import { cn } from '@/utils/cn';

export function ChartFrame({ children, height = 280, className }: { children: ReactNode; height?: number; className?: string }) {
  return (
    <div className={cn('rounded border border-gray-800 bg-gray-950 p-3', className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  );
}
