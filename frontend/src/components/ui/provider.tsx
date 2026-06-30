import type { ReactNode } from 'react';
import { TooltipProvider } from '@radix-ui/react-tooltip';

export function UIProvider({ children }: { children: ReactNode }) {
  return (
    <TooltipProvider delayDuration={250} skipDelayDuration={100}>
      {children}
    </TooltipProvider>
  );
}
