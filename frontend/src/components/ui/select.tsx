import type { ComponentPropsWithoutRef, ElementRef } from 'react';
import { forwardRef } from 'react';
import * as SelectPrimitive from '@radix-ui/react-select';
import { cn } from '@/utils/cn';

export const Select = SelectPrimitive.Root;
export const SelectGroup = SelectPrimitive.Group;
export const SelectValue = SelectPrimitive.Value;

export const SelectTrigger = forwardRef<ElementRef<typeof SelectPrimitive.Trigger>, ComponentPropsWithoutRef<typeof SelectPrimitive.Trigger>>(
  ({ className, children, ...props }, ref) => (
    <SelectPrimitive.Trigger
      ref={ref}
      className={cn('flex h-10 w-full items-center justify-between rounded border border-gray-700 bg-gray-800 px-3 text-sm text-gray-200 outline-none focus:border-mitre-accent', className)}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon className="text-gray-500">▾</SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  )
);
SelectTrigger.displayName = 'SelectTrigger';

export function SelectContent({ className, ...props }: ComponentPropsWithoutRef<typeof SelectPrimitive.Content>) {
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content className={cn('z-50 max-h-80 min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded border border-gray-700 bg-gray-950 text-sm text-gray-200 shadow-xl', className)} {...props}>
        <SelectPrimitive.Viewport className="p-1">{props.children}</SelectPrimitive.Viewport>
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  );
}

export const SelectItem = forwardRef<ElementRef<typeof SelectPrimitive.Item>, ComponentPropsWithoutRef<typeof SelectPrimitive.Item>>(
  ({ className, children, ...props }, ref) => (
    <SelectPrimitive.Item ref={ref} className={cn('relative cursor-pointer rounded px-3 py-2 outline-none data-[highlighted]:bg-gray-800 data-[highlighted]:text-white', className)} {...props}>
      <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
    </SelectPrimitive.Item>
  )
);
SelectItem.displayName = 'SelectItem';
