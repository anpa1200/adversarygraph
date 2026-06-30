import type { ComponentPropsWithoutRef } from 'react';
import * as PopoverPrimitive from '@radix-ui/react-popover';
import { cn } from '@/utils/cn';

export const Popover = PopoverPrimitive.Root;
export const PopoverTrigger = PopoverPrimitive.Trigger;

export function PopoverContent({ className, align = 'start', sideOffset = 6, ...props }: ComponentPropsWithoutRef<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        align={align}
        sideOffset={sideOffset}
        className={cn('z-50 rounded border border-gray-700 bg-gray-950 p-3 text-sm text-gray-200 shadow-xl', className)}
        {...props}
      />
    </PopoverPrimitive.Portal>
  );
}
