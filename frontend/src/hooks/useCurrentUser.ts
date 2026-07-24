import { useQuery } from '@tanstack/react-query';
import { authApi, type CurrentUser } from '@/api/client';


export function useCurrentUser() {
  return useQuery<CurrentUser>({
    queryKey: ['current-user'],
    queryFn: authApi.me,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

export function hasRole(user: CurrentUser | undefined, role: string): boolean {
  if (!user) return false;
  // When auth is disabled the backend treats every request as authenticated with
  // the default role, but local dev shouldn't be gated — treat auth-off as
  // full access.
  if (!user.auth_enabled) return true;
  if (user.roles.includes(role) || user.roles.includes('admin')) return true;
  if (role === 'analyst') return hasPermission(user, 'run_analysis');
  if (role === 'admin') return hasPermission(user, 'manage_auth');
  return false;
}

export function hasPermission(user: CurrentUser | undefined, permission: string): boolean {
  if (!user) return false;
  if (!user.auth_enabled) return true;
  return user.roles.includes('admin') || Boolean(user.permissions?.includes(permission));
}

export function hasModule(user: CurrentUser | undefined, module: string): boolean {
  if (!user) return false;
  if (!user.auth_enabled) return true;
  if (user.roles.includes('admin')) return true;
  // Preserve the previous UI during a rolling frontend/backend deployment.
  // The backend remains authoritative until the newer /auth/me module claim
  // is available.
  if (user.modules === undefined) return true;
  return user.modules.includes(module);
}

/** Effective permission check backed by the shared current-user query. */
export function useHasPermission(permission: string): boolean {
  const { data: user } = useCurrentUser();
  return hasPermission(user, permission);
}

export function useHasModule(module: string): boolean {
  const { data: user } = useCurrentUser();
  return hasModule(user, module);
}
