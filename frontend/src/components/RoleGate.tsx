import type { ReactNode } from 'react';
import { useCurrentUser, hasRole } from '@/hooks/useCurrentUser';

interface RoleGateProps {
  /** Minimum role required. 'analyst' covers analyst + admin. */
  require: 'analyst' | 'admin';
  children: ReactNode;
  /** Shown in place of children when the user lacks the role. */
  fallback?: ReactNode;
}

const DefaultFallback = () => (
  <div className="flex flex-col items-center justify-center h-full gap-3 text-gray-500 p-8">
    <svg className="w-10 h-10 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
        d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
    </svg>
    <p className="text-sm font-medium text-gray-400">Read-only access</p>
    <p className="text-xs text-center max-w-xs">
      Your account has viewer permissions. Contact an administrator to request analyst access.
    </p>
  </div>
);

/**
 * Renders children when the current user has the required role.
 * Falls back to a "read-only access" screen for under-privileged users.
 * When AUTH_ENABLED=false (local dev), role checks are skipped.
 */
export function RoleGate({ require, children, fallback }: RoleGateProps) {
  const { data: user, isLoading } = useCurrentUser();

  // While loading, render children optimistically — the backend is authoritative.
  if (isLoading) return <>{children}</>;

  if (user?.auth_enabled === false) {
    return <>{children}</>;
  }

  if (!hasRole(user, require)) {
    return <>{fallback ?? <DefaultFallback />}</>;
  }

  return <>{children}</>;
}
