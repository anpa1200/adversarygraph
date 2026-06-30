import type { ComponentPropsWithoutRef } from 'react';
import { Command as CommandPrimitive } from 'cmdk';
import { cn } from '@/utils/cn';
import { Dialog, DialogContent } from './dialog';

export function Command({ className, ...props }: ComponentPropsWithoutRef<typeof CommandPrimitive>) {
  return <CommandPrimitive className={cn('flex h-full w-full flex-col overflow-hidden rounded bg-gray-950 text-gray-100', className)} {...props} />;
}

export function CommandDialog({ open, onOpenChange, children }: { open: boolean; onOpenChange: (open: boolean) => void; children: React.ReactNode }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[min(92vw,720px)]">
        <Command>{children}</Command>
      </DialogContent>
    </Dialog>
  );
}

export function CommandInput(props: ComponentPropsWithoutRef<typeof CommandPrimitive.Input>) {
  return <CommandPrimitive.Input className="w-full border-b border-gray-800 bg-transparent px-4 py-3 text-sm outline-none placeholder:text-gray-600" {...props} />;
}

export const CommandList = CommandPrimitive.List;
export const CommandEmpty = CommandPrimitive.Empty;
export const CommandGroup = CommandPrimitive.Group;

export function CommandItem({ className, ...props }: ComponentPropsWithoutRef<typeof CommandPrimitive.Item>) {
  return <CommandPrimitive.Item className={cn('cursor-pointer px-3 py-2 text-sm text-gray-300 aria-selected:bg-gray-800 aria-selected:text-white', className)} {...props} />;
}
