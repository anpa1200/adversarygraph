import type { ReactNode } from 'react';
import { useCurrentUser, hasModule, hasPermission, hasRole } from '@/hooks/useCurrentUser';

interface RoleGateProps {
  /** Minimum role required. 'analyst' covers analyst + admin. */
  require?: 'analyst' | 'admin';
  /** Effective permission accepted by the corresponding backend endpoint. */
  permission?: string;
  /** Grants access when any listed effective permission is present. */
  anyPermission?: string[];
  /** Module visibility grant enforced by the corresponding backend router. */
  module?: string;
  /** Grants access when any listed module is assigned. */
  anyModule?: string[];
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
    <p className="text-sm font-medium text-gray-400">Access unavailable</p>
    <p className="text-xs text-center max-w-xs">
      Your account does not have the permission required for this workspace. Contact an administrator if you need access.
    </p>
  </div>
);

const LoadingFallback = () => (
  <div role="status" className="flex h-full items-center justify-center p-8 text-sm text-gray-500">
    Verifying access…
  </div>
);

/**
 * Renders children when the current user has the required role.
 * Falls back to a "read-only access" screen for under-privileged users.
 * When AUTH_ENABLED=false (local dev), role checks are skipped.
 */
export function RoleGate({ require, permission, anyPermission, module, anyModule, children, fallback }: RoleGateProps) {
  const { data: user, isLoading } = useCurrentUser();

  if (isLoading) return <LoadingFallback />;

  if (user?.auth_enabled === false) {
    return <>{children}</>;
  }

  const checks = [
    require ? hasRole(user, require) : true,
    permission ? hasPermission(user, permission) : true,
    anyPermission?.length ? anyPermission.some(item => hasPermission(user, item)) : true,
    module ? hasModule(user, module) : true,
    anyModule?.length ? anyModule.some(item => hasModule(user, item)) : true,
  ];
  const hasRequirement = Boolean(require || permission || anyPermission?.length || module || anyModule?.length);
  const allowed = hasRequirement && checks.every(Boolean);
  if (!allowed) {
    return <>{fallback ?? <DefaultFallback />}</>;
  }

  return <>{children}</>;
}
