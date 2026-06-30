import type { ComponentPropsWithoutRef } from 'react';
import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import { cn } from '@/utils/cn';

export const Tooltip = TooltipPrimitive.Root;
export const TooltipTrigger = TooltipPrimitive.Trigger;

export function TooltipContent({ className, sideOffset = 6, ...props }: ComponentPropsWithoutRef<typeof TooltipPrimitive.Content>) {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content sideOffset={sideOffset} className={cn('z-50 rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-gray-200 shadow-xl', className)} {...props} />
    </TooltipPrimitive.Portal>
  );
}
