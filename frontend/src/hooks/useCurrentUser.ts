import { useQuery } from '@tanstack/react-query';
import { pipelineApi } from '@/api/client';

export type CurrentUser = { name: string; roles: string[]; auth_enabled: boolean };

export function useCurrentUser() {
  return useQuery<CurrentUser>({
    queryKey: ['pipeline-me'],
    queryFn: pipelineApi.me,
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
  return user.roles.includes(role) || user.roles.includes('admin');
}
