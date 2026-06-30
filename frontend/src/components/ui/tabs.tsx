import type { ComponentPropsWithoutRef, ElementRef } from 'react';
import { forwardRef } from 'react';
import * as TabsPrimitive from '@radix-ui/react-tabs';
import { cn } from '@/utils/cn';

export const Tabs = TabsPrimitive.Root;

export const TabsList = forwardRef<ElementRef<typeof TabsPrimitive.List>, ComponentPropsWithoutRef<typeof TabsPrimitive.List>>(
  ({ className, ...props }, ref) => (
    <TabsPrimitive.List ref={ref} className={cn('flex flex-wrap gap-2 border-b border-gray-800 p-2', className)} {...props} />
  )
);
TabsList.displayName = 'TabsList';

export const TabsTrigger = forwardRef<ElementRef<typeof TabsPrimitive.Trigger>, ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>>(
  ({ className, ...props }, ref) => (
    <TabsPrimitive.Trigger
      ref={ref}
      className={cn(
        'rounded border border-gray-700 px-3 py-1.5 text-xs font-semibold text-gray-400 data-[state=active]:border-mitre-accent data-[state=active]:bg-mitre-accent/15 data-[state=active]:text-white',
        className
      )}
      {...props}
    />
  )
);
TabsTrigger.displayName = 'TabsTrigger';

export const TabsContent = forwardRef<ElementRef<typeof TabsPrimitive.Content>, ComponentPropsWithoutRef<typeof TabsPrimitive.Content>>(
  ({ className, ...props }, ref) => <TabsPrimitive.Content ref={ref} className={cn('outline-none', className)} {...props} />
);
TabsContent.displayName = 'TabsContent';
