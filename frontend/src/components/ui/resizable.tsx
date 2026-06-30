import type { ComponentPropsWithoutRef } from 'react';
import { Group, Panel, Separator } from 'react-resizable-panels';
import { cn } from '@/utils/cn';

export const ResizablePanelGroup = Group;
export const ResizablePanel = Panel;

export function ResizableHandle({ className, ...props }: ComponentPropsWithoutRef<typeof Separator>) {
  return <Separator className={cn('w-1 bg-gray-800 transition-colors hover:bg-mitre-accent data-[resize-handle-active]:bg-mitre-accent', className)} {...props} />;
}
