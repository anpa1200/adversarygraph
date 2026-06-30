import { FormEvent, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { authApi, type AuthStatus } from '@/api/client';
import adversaryGraphIcon from '@/assets/adversarygraph-ai-icon-192.png';

export function Login({ status }: { status?: AuthStatus }) {
  const qc = useQueryClient();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const login = useMutation({
    mutationFn: authApi.login,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['current-user'] });
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    login.mutate({ username, password });
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-mitre-dark px-6">
      <div className="w-full max-w-md rounded border border-gray-700 bg-mitre-navy shadow-2xl">
        <div className="border-b border-gray-700 p-6">
          <div className="flex items-center gap-3">
            <img src={adversaryGraphIcon} alt="" className="h-10 w-10 rounded-lg object-cover" />
            <div>
              <h1 className="text-lg font-bold text-white">AdversaryGraph</h1>
              <p className="text-xs text-gray-500">Protected analyst workspace</p>
            </div>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-4 p-6">
          {status?.bootstrap_required && (
            <div className="rounded border border-amber-500/50 bg-amber-950/30 p-3 text-xs leading-5 text-amber-100">
              Authentication is enabled but no native users exist. Set
              <code className="mx-1 rounded bg-black/30 px-1">AUTH_BOOTSTRAP_ADMIN_PASSWORD</code>
              and restart the API container to create the first administrator.
            </div>
          )}
          <label className="block">
            <span className="label">Username</span>
            <input className="field" value={username} onChange={event => setUsername(event.target.value)} autoComplete="username" />
          </label>
          <label className="block">
            <span className="label">Password</span>
            <input className="field" type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" />
          </label>
          {login.error && <div className="rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">{login.error.message}</div>}
          <button className="primary w-full" disabled={login.isPending || !username || !password}>
            {login.isPending ? 'Signing in...' : 'Sign in'}
          </button>
          <p className="text-xs leading-5 text-gray-500">
            Native username/password auth can run alone or beside trusted reverse-proxy header auth.
          </p>
        </form>
      </div>
    </div>
  );
}
