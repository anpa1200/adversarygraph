import type { ComponentPropsWithoutRef, ElementRef } from 'react';
import { forwardRef } from 'react';
import * as ScrollAreaPrimitive from '@radix-ui/react-scroll-area';
import { cn } from '@/utils/cn';

export const ScrollArea = forwardRef<ElementRef<typeof ScrollAreaPrimitive.Root>, ComponentPropsWithoutRef<typeof ScrollAreaPrimitive.Root>>(
  ({ className, children, ...props }, ref) => (
    <ScrollAreaPrimitive.Root ref={ref} className={cn('relative overflow-hidden', className)} {...props}>
      <ScrollAreaPrimitive.Viewport className="h-full w-full rounded-[inherit]">{children}</ScrollAreaPrimitive.Viewport>
      <ScrollAreaPrimitive.Scrollbar orientation="vertical" className="flex w-2.5 touch-none select-none p-0.5">
        <ScrollAreaPrimitive.Thumb className="relative flex-1 rounded bg-gray-700" />
      </ScrollAreaPrimitive.Scrollbar>
      <ScrollAreaPrimitive.Scrollbar orientation="horizontal" className="flex h-2.5 touch-none select-none p-0.5">
        <ScrollAreaPrimitive.Thumb className="relative flex-1 rounded bg-gray-700" />
      </ScrollAreaPrimitive.Scrollbar>
      <ScrollAreaPrimitive.Corner />
    </ScrollAreaPrimitive.Root>
  )
);
ScrollArea.displayName = 'ScrollArea';
