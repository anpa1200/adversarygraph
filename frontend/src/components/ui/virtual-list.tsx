import type { ReactNode } from 'react';
import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

export function VirtualList<T>({
  items,
  estimateSize = 36,
  height = 420,
  renderItem,
}: {
  items: T[];
  estimateSize?: number;
  height?: number | string;
  renderItem: (item: T, index: number) => ReactNode;
}) {
  const parentRef = useRef<HTMLDivElement | null>(null);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => estimateSize,
    overscan: 12,
  });

  return (
    <div ref={parentRef} className="overflow-auto" style={{ height }}>
      <div className="relative w-full" style={{ height: virtualizer.getTotalSize() }}>
        {virtualizer.getVirtualItems().map(virtualRow => (
          <div
            key={virtualRow.key}
            className="absolute left-0 top-0 w-full"
            style={{ transform: `translateY(${virtualRow.start}px)` }}
          >
            {renderItem(items[virtualRow.index], virtualRow.index)}
          </div>
        ))}
      </div>
    </div>
  );
}
