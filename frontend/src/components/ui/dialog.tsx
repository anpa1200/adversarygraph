import type { ComponentPropsWithoutRef, ElementRef, ReactNode } from 'react';
import { forwardRef } from 'react';
import * as DialogPrimitive from '@radix-ui/react-dialog';
import { cn } from '@/utils/cn';

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

export function DialogContent({ className, children, ...props }: ComponentPropsWithoutRef<typeof DialogPrimitive.Content>) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm" />
      <DialogPrimitive.Content
        className={cn(
          'fixed left-1/2 top-1/2 z-50 max-h-[86vh] w-[min(92vw,920px)] -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded border border-gray-700 bg-gray-950 text-gray-100 shadow-2xl',
          className
        )}
        {...props}
      >
        {children}
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export const DialogTitle = forwardRef<ElementRef<typeof DialogPrimitive.Title>, ComponentPropsWithoutRef<typeof DialogPrimitive.Title>>(
  ({ className, ...props }, ref) => (
    <DialogPrimitive.Title ref={ref} className={cn('px-4 py-3 text-sm font-semibold text-white', className)} {...props} />
  )
);
DialogTitle.displayName = 'DialogTitle';

export const DialogDescription = forwardRef<
  ElementRef<typeof DialogPrimitive.Description>,
  ComponentPropsWithoutRef<typeof DialogPrimitive.Description>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Description ref={ref} className={cn('px-4 text-xs leading-relaxed text-gray-400', className)} {...props} />
));
DialogDescription.displayName = 'DialogDescription';

export function DialogBody({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn('max-h-[72vh] overflow-y-auto p-4', className)}>{children}</div>;
}
