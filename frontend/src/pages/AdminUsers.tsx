import { FormEvent, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authApi, type ManagedUser } from '@/api/client';
import { Header } from '@/components/Layout/Header';

const roles = ['viewer', 'analyst', 'admin'] as const;

function fmt(value: string | null) {
  return value ? new Date(value).toLocaleString() : '-';
}

export function AdminUsers() {
  const qc = useQueryClient();
  const { data: users = [] } = useQuery({ queryKey: ['admin-users'], queryFn: authApi.users });
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<(typeof roles)[number]>('viewer');
  const [enabled, setEnabled] = useState(true);
  const [passwordTarget, setPasswordTarget] = useState<ManagedUser | null>(null);
  const [newPassword, setNewPassword] = useState('');

  const refresh = () => qc.invalidateQueries({ queryKey: ['admin-users'] });
  const createUser = useMutation({ mutationFn: authApi.createUser, onSuccess: () => { setUsername(''); setDisplayName(''); setPassword(''); setRole('viewer'); setEnabled(true); refresh(); } });
  const updateUser = useMutation({ mutationFn: ({ id, body }: { id: string; body: { display_name?: string; role?: string; enabled?: boolean } }) => authApi.updateUser(id, body), onSuccess: refresh });
  const resetPassword = useMutation({ mutationFn: ({ id, password }: { id: string; password: string }) => authApi.setPassword(id, password), onSuccess: () => { setPasswordTarget(null); setNewPassword(''); refresh(); } });

  function submit(event: FormEvent) {
    event.preventDefault();
    createUser.mutate({ username, display_name: displayName, password, role, enabled });
  }

  return (
    <>
      <Header title="Admin Panel" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto grid max-w-7xl gap-6 xl:grid-cols-[420px_1fr]">
          <section className="rounded border border-gray-700 bg-gray-900">
            <div className="border-b border-gray-700 p-4">
              <h2 className="font-semibold text-white">Create user</h2>
            </div>
            <form onSubmit={submit} className="space-y-4 p-4">
              <label className="block"><span className="label">Username</span><input className="field" value={username} onChange={event => setUsername(event.target.value)} /></label>
              <label className="block"><span className="label">Display name</span><input className="field" value={displayName} onChange={event => setDisplayName(event.target.value)} /></label>
              <label className="block"><span className="label">Initial password</span><input className="field" type="password" value={password} onChange={event => setPassword(event.target.value)} /></label>
              <label className="block"><span className="label">Role</span><select className="field" value={role} onChange={event => setRole(event.target.value as (typeof roles)[number])}>{roles.map(item => <option key={item}>{item}</option>)}</select></label>
              <label className="flex items-center gap-2 text-sm text-gray-300"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} /> Enabled</label>
              {createUser.error && <div className="rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">{createUser.error.message}</div>}
              <button className="primary w-full" disabled={createUser.isPending || !username || password.length < 10}>Create user</button>
            </form>
          </section>

          <section className="rounded border border-gray-700 bg-gray-900">
            <div className="border-b border-gray-700 p-4">
              <h2 className="font-semibold text-white">Users</h2>
              <p className="mt-1 text-xs text-gray-500">Viewer is read-only. Analyst can run workflows. Admin can manage users.</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-gray-950 text-xs uppercase text-gray-500">
                  <tr><th className="p-3">User</th><th className="p-3">Role</th><th className="p-3">Status</th><th className="p-3">Last login</th><th className="p-3 text-right">Actions</th></tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {users.map(user => (
                    <tr key={user.id}>
                      <td className="p-3"><div className="font-semibold text-white">{user.username}</div><div className="text-xs text-gray-500">{user.display_name || '-'}</div></td>
                      <td className="p-3"><select className="field min-w-28" value={user.role} onChange={event => updateUser.mutate({ id: user.id, body: { role: event.target.value } })}>{roles.map(item => <option key={item}>{item}</option>)}</select></td>
                      <td className="p-3"><button className={user.enabled ? 'secondary-action border-green-700 text-green-300' : 'secondary-action border-red-700 text-red-300'} onClick={() => updateUser.mutate({ id: user.id, body: { enabled: !user.enabled } })}>{user.enabled ? 'Enabled' : 'Disabled'}</button></td>
                      <td className="p-3 text-xs text-gray-500">{fmt(user.last_login_at)}</td>
                      <td className="p-3 text-right"><button className="secondary-action" onClick={() => setPasswordTarget(user)}>Reset password</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </div>
      {passwordTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6" onClick={() => setPasswordTarget(null)}>
          <form className="w-full max-w-md rounded border border-gray-700 bg-gray-900 p-5" onClick={event => event.stopPropagation()} onSubmit={event => { event.preventDefault(); resetPassword.mutate({ id: passwordTarget.id, password: newPassword }); }}>
            <h3 className="font-semibold text-white">Reset password for {passwordTarget.username}</h3>
            <label className="mt-4 block"><span className="label">New password</span><input className="field" type="password" value={newPassword} onChange={event => setNewPassword(event.target.value)} autoFocus /></label>
            {resetPassword.error && <div className="mt-3 rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">{resetPassword.error.message}</div>}
            <div className="mt-4 flex justify-end gap-2"><button type="button" className="secondary-action" onClick={() => setPasswordTarget(null)}>Cancel</button><button className="primary-action" disabled={newPassword.length < 10}>Save password</button></div>
          </form>
        </div>
      )}
    </>
  );
}
