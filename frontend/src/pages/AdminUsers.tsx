import { FormEvent, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authApi, type AccessGroup, type ManagedUser, type ModuleCatalogItem } from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';

const fallbackRoles = ['viewer', 'analyst', 'threat_intel', 'detection_engineer', 'incident_responder', 'auditor', 'security_admin', 'service_account', 'admin'];
const fallbackPermissions = ['read', 'run_analysis', 'manage_intel', 'manage_detections', 'run_attack_simulation', 'manage_feeds', 'forward_siem', 'upload_files', 'export_data', 'manage_users', 'manage_auth', 'view_audit'];

type PasswordPolicy = NonNullable<Awaited<ReturnType<typeof authApi.status>>['password_policy']>;

function fmt(value: string | null) {
  return value ? new Date(value).toLocaleString() : '-';
}

function passwordProblems(password: string, policy: PasswordPolicy): string[] {
  const problems: string[] = [];
  if (password.length < policy.min_length) problems.push(`Use at least ${policy.min_length} characters.`);
  if (policy.require_upper && !/[A-Z]/.test(password)) problems.push('Add an uppercase letter.');
  if (policy.require_lower && !/[a-z]/.test(password)) problems.push('Add a lowercase letter.');
  if (policy.require_number && !/[0-9]/.test(password)) problems.push('Add a number.');
  if (policy.require_special && !/[^A-Za-z0-9]/.test(password)) problems.push('Add a special character.');
  return problems;
}

function TogglePermission({ value, selected, onChange, disabled = false }: { value: string; selected: boolean; onChange: (next: boolean) => void; disabled?: boolean }) {
  return (
    <label className={`flex cursor-pointer items-center gap-2 rounded border px-2 py-1 text-xs ${selected ? 'border-mitre-accent bg-mitre-accent/10 text-white' : 'border-gray-700 bg-gray-950 text-gray-400'}`}>
      <input type="checkbox" disabled={disabled} checked={selected} onChange={event => onChange(event.target.checked)} />
      {value}
    </label>
  );
}

export function AdminUsers() {
  const qc = useQueryClient();
  const canManageUsers = useHasPermission('manage_users');
  const canManageAuth = useHasPermission('manage_auth');
  const canViewAudit = useHasPermission('view_audit');
  const canReadUsers = canManageUsers || canManageAuth;
  const { data: status } = useQuery({ queryKey: ['auth-status-admin'], queryFn: authApi.status });
  const { data: users = [] } = useQuery({ queryKey: ['admin-users'], queryFn: authApi.users, enabled: canReadUsers });
  const { data: groups = [] } = useQuery({ queryKey: ['admin-groups'], queryFn: authApi.groups, enabled: canReadUsers });
  const { data: sessions = [] } = useQuery({ queryKey: ['admin-sessions'], queryFn: authApi.sessions, enabled: canManageAuth });
  const { data: audit = [] } = useQuery({ queryKey: ['auth-audit'], queryFn: authApi.audit, enabled: canViewAudit });

  const roles = status?.roles?.length ? status.roles : fallbackRoles;
  const permissions = status?.permissions?.length ? status.permissions : fallbackPermissions;
  const policy = status?.password_policy;
  const minPasswordLength = policy?.min_length ?? 12;
  const effectivePasswordPolicy: PasswordPolicy = policy ?? {
    min_length: minPasswordLength,
    require_upper: false,
    require_lower: false,
    require_number: false,
    require_special: false,
    mfa_available: false,
    mfa_required: false,
  };

  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('viewer');
  const [extraPermissions, setExtraPermissions] = useState<string[]>([]);
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [createAttempted, setCreateAttempted] = useState(false);
  const [createValidation, setCreateValidation] = useState<string[]>([]);
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupSlug, setNewGroupSlug] = useState('');
  const [groupSlugTouched, setGroupSlugTouched] = useState(false);
  const [newGroupDescription, setNewGroupDescription] = useState('');
  const [passwordTarget, setPasswordTarget] = useState<ManagedUser | null>(null);
  const [newPassword, setNewPassword] = useState('');

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['admin-users'] });
    qc.invalidateQueries({ queryKey: ['admin-groups'] });
    qc.invalidateQueries({ queryKey: ['admin-sessions'] });
    qc.invalidateQueries({ queryKey: ['auth-audit'] });
  };
  const createUser = useMutation({ mutationFn: authApi.createUser, onSuccess: () => { setUsername(''); setDisplayName(''); setPassword(''); setRole('viewer'); setExtraPermissions([]); setGroupIds([]); setEnabled(true); setCreateAttempted(false); setCreateValidation([]); refresh(); } });
  const updateUser = useMutation({ mutationFn: ({ id, body }: { id: string; body: { display_name?: string; role?: string; permissions?: string[]; group_ids?: string[]; enabled?: boolean } }) => authApi.updateUser(id, body), onSuccess: refresh });
  const createGroup = useMutation({
    mutationFn: authApi.createGroup,
    onSuccess: () => {
      setNewGroupName('');
      setNewGroupSlug('');
      setGroupSlugTouched(false);
      setNewGroupDescription('');
      refresh();
    },
  });
  const updateGroup = useMutation({ mutationFn: ({ id, body }: { id: string; body: Parameters<typeof authApi.updateGroup>[1] }) => authApi.updateGroup(id, body), onSuccess: refresh });
  const deleteGroup = useMutation({ mutationFn: authApi.deleteGroup, onSuccess: refresh });
  const resetPassword = useMutation({ mutationFn: ({ id, password }: { id: string; password: string }) => authApi.setPassword(id, password), onSuccess: () => { setPasswordTarget(null); setNewPassword(''); refresh(); } });
  const revokeSessions = useMutation({ mutationFn: authApi.revokeUserSessions, onSuccess: refresh });
  const disableMfa = useMutation({ mutationFn: authApi.disableMfa, onSuccess: refresh });

  const activeSessionCount = useMemo(() => sessions.filter(item => item.active).length, [sessions]);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!canManageUsers) return;
    // Read the submitted controls as well as React state so browser/password-
    // manager autofill cannot leave a valid-looking form permanently disabled.
    const form = event.currentTarget as HTMLFormElement;
    const values = new FormData(form);
    const submittedUsername = String(values.get('username') ?? '').trim();
    const submittedDisplayName = String(values.get('display_name') ?? '').trim();
    const submittedPassword = String(values.get('password') ?? '');
    const problems = [
      ...(!submittedUsername ? ['Enter a username.'] : []),
      ...passwordProblems(submittedPassword, effectivePasswordPolicy),
    ];
    setCreateAttempted(true);
    setCreateValidation(problems);
    setUsername(submittedUsername);
    setDisplayName(submittedDisplayName);
    setPassword(submittedPassword);
    if (problems.length) return;
    createUser.mutate({ username: submittedUsername, display_name: submittedDisplayName, password: submittedPassword, role, permissions: extraPermissions, group_ids: groupIds, enabled });
  }

  function updatePermissions(user: ManagedUser, permission: string, selected: boolean) {
    if (!canManageUsers) return;
    const current = new Set(user.permissions || []);
    if (selected) current.add(permission); else current.delete(permission);
    updateUser.mutate({ id: user.id, body: { permissions: [...current].sort() } });
  }

  return (
    <>
      <Header title="Admin Panel" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto grid max-w-7xl gap-6">
          {status?.auth_enabled === false && (
            <section className="rounded border border-amber-500/50 bg-amber-950/25 p-4 text-sm leading-6 text-amber-100">
              <strong>Access enforcement is currently disabled.</strong>{' '}
              You can prepare users and group assignments now, but all requests remain unrestricted until the operator sets
              <code className="mx-1 rounded bg-black/30 px-1.5 py-0.5">AUTH_ENABLED=true</code>
              and restarts the API. Confirm a working administrator account before enabling it.
            </section>
          )}
          <section className="grid gap-4 md:grid-cols-3 xl:grid-cols-5">
            <Metric label="Users" value={canReadUsers ? String(users.length) : '-'} />
            <Metric label="Active sessions" value={canManageAuth ? String(activeSessionCount) : '-'} />
            <Metric label="Access groups" value={canReadUsers ? String(groups.length) : '-'} />
            <Metric label="SSO mode" value={status?.sso_mode || 'proxy'} />
            <Metric label="Password minimum" value={`${minPasswordLength} chars`} />
          </section>

          <section className="grid gap-6 xl:grid-cols-[420px_1fr]">
            <div className="rounded border border-gray-700 bg-gray-900">
              <div className="border-b border-gray-700 p-4">
                <h2 className="font-semibold text-white">Create user</h2>
                <p className="mt-1 text-xs text-gray-500">Use named accounts and assign the smallest practical SOC group set.</p>
              </div>
              {canManageUsers ? <form onSubmit={submit} noValidate className="space-y-4 p-4">
                <label className="block">
                  <span className="label">Username</span>
                  <input
                    className="field"
                    name="username"
                    autoComplete="off"
                    required
                    aria-invalid={createAttempted && !username.trim()}
                    value={username}
                    onChange={event => {
                      setUsername(event.target.value);
                      if (createAttempted) setCreateValidation([]);
                    }}
                  />
                  {createAttempted && !username.trim() && <span className="mt-1 block text-xs text-red-300">Username is required.</span>}
                </label>
                <label className="block">
                  <span className="label">Display name</span>
                  <input className="field" name="display_name" autoComplete="off" value={displayName} onChange={event => setDisplayName(event.target.value)} />
                </label>
                <label className="block">
                  <span className="label">Initial password</span>
                  <input
                    className="field"
                    name="password"
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={minPasswordLength}
                    aria-describedby="create-user-password-policy"
                    aria-invalid={createAttempted && passwordProblems(password, effectivePasswordPolicy).length > 0}
                    value={password}
                    onChange={event => {
                      setPassword(event.target.value);
                      if (createAttempted) setCreateValidation([]);
                    }}
                  />
                  <span id="create-user-password-policy" className="mt-1 block text-xs text-gray-500">
                    Minimum {minPasswordLength} characters
                    {effectivePasswordPolicy.require_upper ? ' · uppercase' : ''}
                    {effectivePasswordPolicy.require_lower ? ' · lowercase' : ''}
                    {effectivePasswordPolicy.require_number ? ' · number' : ''}
                    {effectivePasswordPolicy.require_special ? ' · special character' : ''}.
                  </span>
                </label>
                <div>
                  <span className="label">SOC groups</span>
                  <p className="mb-2 mt-1 text-xs text-gray-500">Groups control which modules appear and which actions are allowed.</p>
                  <GroupPicker groups={groups} selected={groupIds} onChange={setGroupIds} />
                </div>
                <details className="rounded border border-gray-700 bg-gray-950/40 p-3">
                  <summary className="cursor-pointer text-xs font-semibold text-gray-300">Advanced role and direct grants</summary>
                  <label className="mt-3 block"><span className="label">Legacy baseline role</span><select className="field" value={role} onChange={event => setRole(event.target.value)}>{roles.map(item => <option key={item}>{item}</option>)}</select></label>
                <div>
                  <span className="label">Extra permissions</span>
                  <div className="mt-2 grid max-h-52 gap-2 overflow-y-auto pr-1">
                    {permissions.map(item => (
                      <TogglePermission key={item} value={item} selected={extraPermissions.includes(item)} onChange={next => setExtraPermissions(prev => next ? [...new Set([...prev, item])].sort() : prev.filter(p => p !== item))} />
                    ))}
                  </div>
                </div>
                </details>
                <label className="flex items-center gap-2 text-sm text-gray-300"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} /> Enabled</label>
                {createValidation.length > 0 && (
                  <div role="alert" className="rounded border border-amber-500/40 bg-amber-950/30 p-3 text-xs text-amber-100">
                    <div className="font-semibold">Complete these fields to create the user:</div>
                    <ul className="mt-1 list-disc space-y-1 pl-5">
                      {createValidation.map(problem => <li key={problem}>{problem}</li>)}
                    </ul>
                  </div>
                )}
                {createUser.error && <div className="rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">{createUser.error.message}</div>}
                <button className="primary w-full" disabled={createUser.isPending}>
                  {createUser.isPending ? 'Creating user…' : 'Create user'}
                </button>
              </form> : <div className="p-4"><PermissionNotice permission="manage_users" action="create user accounts" /></div>}
            </div>

            <div className="rounded border border-gray-700 bg-gray-900">
              <div className="border-b border-gray-700 p-4">
                <h2 className="font-semibold text-white">Users and permissions</h2>
                <p className="mt-1 text-xs text-gray-500">Groups control modules and team capabilities. Baseline roles and direct grants remain available for compatibility.</p>
              </div>
              <div className="overflow-x-auto">
                {!canReadUsers && <div className="p-4"><PermissionNotice permission="manage_users" action="view the user directory; manage_auth is also accepted" /></div>}
                {canReadUsers && (
                <table className="w-full min-w-[1180px] text-left text-sm">
                  <thead className="bg-gray-950 text-xs uppercase text-gray-500">
                    <tr><th className="p-3">User</th><th className="p-3">SOC groups</th><th className="p-3">Baseline role</th><th className="p-3">Direct grants</th><th className="p-3">Security</th><th className="p-3">Last login</th><th className="p-3 text-right">Actions</th></tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {users.map(user => (
                      <tr key={user.id}>
                        <td className="p-3 align-top"><div className="font-semibold text-white">{user.username}</div><div className="text-xs text-gray-500">{user.display_name || '-'}</div><div className="mt-1 text-[10px] text-gray-600">{user.auth_provider}</div></td>
                        <td className="min-w-72 p-3 align-top">
                          <UserGroupAssignmentEditor
                            groups={groups}
                            user={user}
                            disabled={!canManageUsers}
                            onSave={next => updateUser.mutate({ id: user.id, body: { group_ids: next } })}
                          />
                          <div className="mt-2 text-[10px] text-gray-600">{user.effective_modules?.length || 0} modules</div>
                        </td>
                        <td className="p-3 align-top"><select disabled={!canManageUsers} className="field min-w-44" value={user.role} onChange={event => updateUser.mutate({ id: user.id, body: { role: event.target.value } })}>{roles.map(item => <option key={item}>{item}</option>)}</select></td>
                        <td className="p-3 align-top">
                          <div className="grid max-h-40 min-w-72 gap-1 overflow-y-auto pr-1">
                            {permissions.map(item => <TogglePermission disabled={!canManageUsers} key={item} value={item} selected={(user.permissions || []).includes(item)} onChange={next => updatePermissions(user, item, next)} />)}
                          </div>
                        </td>
                        <td className="p-3 align-top text-xs">
                          {canManageUsers ? <button className={user.enabled ? 'secondary-action border-green-700 text-green-300' : 'secondary-action border-red-700 text-red-300'} onClick={() => updateUser.mutate({ id: user.id, body: { enabled: !user.enabled } })}>{user.enabled ? 'Enabled' : 'Disabled'}</button> : <span className={user.enabled ? 'text-green-300' : 'text-red-300'}>{user.enabled ? 'Enabled' : 'Disabled'}</span>}
                          <div className="mt-2 text-gray-500">MFA: {user.mfa_enabled ? 'enabled' : 'off'}</div>
                        </td>
                        <td className="p-3 align-top text-xs text-gray-500">{fmt(user.last_login_at)}</td>
                        <td className="space-y-2 p-3 text-right align-top">
                          {canManageUsers && <button className="secondary-action" onClick={() => setPasswordTarget(user)}>Reset password</button>}
                          {canManageAuth && <button className="secondary-action" onClick={() => revokeSessions.mutate(user.id)}>Revoke sessions</button>}
                          {canManageAuth && user.mfa_enabled && <button className="secondary-action border-amber-700 text-amber-200" onClick={() => disableMfa.mutate(user.id)}>Disable MFA</button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                )}
              </div>
            </div>
          </section>

          <section className="grid gap-6 xl:grid-cols-[360px_1fr]">
            <div className="rounded border border-gray-700 bg-gray-900">
              <div className="border-b border-gray-700 p-4">
                <h2 className="font-semibold text-white">Create access group</h2>
                <p className="mt-1 text-xs text-gray-500">Create a local team profile when the built-in SOC structures do not fit.</p>
              </div>
              {canManageUsers ? (
                <form
                  className="space-y-4 p-4"
                  onSubmit={event => {
                    event.preventDefault();
                    createGroup.mutate({
                      name: newGroupName,
                      slug: newGroupSlug,
                      description: newGroupDescription,
                      permissions: ['read'],
                      modules: ['discover', 'help'],
                      enabled: true,
                    });
                  }}
                >
                  <label className="block"><span className="label">Name</span><input className="field" value={newGroupName} onChange={event => {
                    setNewGroupName(event.target.value);
                    if (!groupSlugTouched) setNewGroupSlug(event.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''));
                  }} /></label>
                  <label className="block"><span className="label">Slug</span><input className="field font-mono" value={newGroupSlug} onChange={event => {
                    setGroupSlugTouched(true);
                    setNewGroupSlug(event.target.value.toLowerCase());
                  }} /></label>
                  <label className="block"><span className="label">Purpose</span><textarea className="field min-h-24" value={newGroupDescription} onChange={event => setNewGroupDescription(event.target.value)} /></label>
                  {createGroup.error && <div className="rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">{createGroup.error.message}</div>}
                  <button className="primary w-full" disabled={!newGroupName || !newGroupSlug || createGroup.isPending}>Create least-privilege group</button>
                </form>
              ) : <div className="p-4"><PermissionNotice permission="manage_users" action="create access groups" /></div>}
            </div>
            <div className="rounded border border-gray-700 bg-gray-900">
              <div className="border-b border-gray-700 p-4">
                <h2 className="font-semibold text-white">SOC access profiles</h2>
                <p className="mt-1 text-xs text-gray-500">Module visibility and action permissions are enforced by the frontend and API. Built-in profiles are seeded once and remain locally editable by administrators.</p>
              </div>
              <div className="grid gap-3 p-4">
                {groups.map(group => (
                  <GroupPolicyEditor
                    key={group.id}
                    group={group}
                    permissions={permissions}
                    modules={status?.module_catalog || []}
                    disabled={!canManageUsers}
                    onUpdate={body => updateGroup.mutate({ id: group.id, body })}
                    onDelete={() => deleteGroup.mutate(group.id)}
                  />
                ))}
              </div>
            </div>
          </section>

          <section className="grid gap-6 xl:grid-cols-2">
            {canManageAuth ? <Panel title="Recent sessions">
              <table className="w-full text-left text-xs">
                <thead className="text-gray-500"><tr><th className="py-2">User</th><th>IP</th><th>Status</th><th>Expires</th></tr></thead>
                <tbody className="divide-y divide-gray-800">
                  {sessions.slice(0, 20).map(item => <tr key={item.id}><td className="py-2 text-white">{item.username}</td><td>{item.ip_address || '-'}</td><td className={item.active ? 'text-green-300' : 'text-gray-500'}>{item.active ? 'active' : 'closed'}</td><td>{fmt(item.expires_at)}</td></tr>)}
                </tbody>
              </table>
            </Panel> : <Panel title="Recent sessions"><PermissionNotice permission="manage_auth" action="view active authentication sessions" compact /></Panel>}
            {canViewAudit ? <Panel title="Auth audit trail">
              <table className="w-full text-left text-xs">
                <thead className="text-gray-500"><tr><th className="py-2">Time</th><th>Actor</th><th>Action</th><th>Object</th></tr></thead>
                <tbody className="divide-y divide-gray-800">
                  {audit.slice(0, 20).map(item => <tr key={item.id}><td className="py-2">{fmt(item.created_at)}</td><td className="text-white">{item.actor}</td><td className="text-mitre-accent">{item.action}</td><td>{item.object_type}</td></tr>)}
                </tbody>
              </table>
            </Panel> : <Panel title="Auth audit trail"><PermissionNotice permission="view_audit" action="view authentication audit events" compact /></Panel>}
          </section>
        </div>
      </div>
      {passwordTarget && canManageUsers && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6" onClick={() => setPasswordTarget(null)}>
          <form className="w-full max-w-md rounded border border-gray-700 bg-gray-900 p-5" onClick={event => event.stopPropagation()} onSubmit={event => { event.preventDefault(); resetPassword.mutate({ id: passwordTarget.id, password: newPassword }); }}>
            <h3 className="font-semibold text-white">Reset password for {passwordTarget.username}</h3>
            <label className="mt-4 block"><span className="label">New password</span><input className="field" type="password" value={newPassword} onChange={event => setNewPassword(event.target.value)} autoFocus /></label>
            {resetPassword.error && <div className="mt-3 rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">{resetPassword.error.message}</div>}
            <div className="mt-4 flex justify-end gap-2"><button type="button" className="secondary-action" onClick={() => setPasswordTarget(null)}>Cancel</button><button className="primary-action" disabled={newPassword.length < minPasswordLength}>Save password</button></div>
          </form>
        </div>
      )}
    </>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="rounded border border-gray-700 bg-gray-900 p-4"><div className="text-2xl font-bold text-white">{value}</div><div className="mt-1 text-xs text-gray-500">{label}</div></div>;
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return <div className="rounded border border-gray-700 bg-gray-900"><div className="border-b border-gray-700 p-4"><h2 className="font-semibold text-white">{title}</h2></div><div className="max-h-96 overflow-auto p-4">{children}</div></div>;
}

function GroupPicker({
  groups,
  selected,
  onChange,
  disabled = false,
}: {
  groups: AccessGroup[];
  selected: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
}) {
  const selectedSet = new Set(selected);
  return (
    <div className="grid max-h-44 gap-1 overflow-y-auto pr-1">
      {groups.filter(group => group.enabled || selectedSet.has(group.id)).map(group => (
        <label
          key={group.id}
          className={`flex cursor-pointer items-start gap-2 rounded border px-2 py-2 text-xs ${
            selectedSet.has(group.id)
              ? 'border-blue-500/60 bg-blue-950/30 text-blue-100'
              : 'border-gray-700 bg-gray-950 text-gray-400'
          }`}
        >
          <input
            className="mt-0.5"
            type="checkbox"
            disabled={disabled || !group.enabled}
            checked={selectedSet.has(group.id)}
            onChange={event => {
              const next = new Set(selected);
              if (event.target.checked) next.add(group.id); else next.delete(group.id);
              onChange([...next]);
            }}
          />
          <span className="min-w-0">
            <span className="block font-semibold">{group.name}</span>
            <span className="block text-[10px] text-gray-500">
              {group.modules.length} modules · {group.member_count} member{group.member_count === 1 ? '' : 's'}
              {!group.enabled ? ' · disabled' : ''}
            </span>
          </span>
        </label>
      ))}
      {!groups.length && <p className="text-xs text-gray-600">No access groups are available yet.</p>}
    </div>
  );
}

function UserGroupAssignmentEditor({
  groups,
  user,
  disabled,
  onSave,
}: {
  groups: AccessGroup[];
  user: ManagedUser;
  disabled: boolean;
  onSave: (groupIds: string[]) => void;
}) {
  const [draft, setDraft] = useState(user.group_ids || []);
  useEffect(() => setDraft(user.group_ids || []), [user.group_ids]);
  const dirty = [...draft].sort().join('|') !== [...(user.group_ids || [])].sort().join('|');
  return (
    <div>
      <GroupPicker groups={groups} selected={draft} disabled={disabled} onChange={setDraft} />
      <button
        type="button"
        disabled={disabled || !dirty}
        className="secondary-action mt-2 w-full disabled:cursor-not-allowed disabled:opacity-40"
        onClick={() => onSave(draft)}
      >
        Save memberships
      </button>
    </div>
  );
}

function GroupPolicyEditor({
  group,
  permissions,
  modules,
  disabled,
  onUpdate,
  onDelete,
}: {
  group: AccessGroup;
  permissions: string[];
  modules: ModuleCatalogItem[];
  disabled: boolean;
  onUpdate: (body: { permissions?: string[]; modules?: string[]; enabled?: boolean }) => void;
  onDelete: () => void;
}) {
  const [draftPermissions, setDraftPermissions] = useState(group.permissions);
  const [draftModules, setDraftModules] = useState(group.modules);
  const [draftEnabled, setDraftEnabled] = useState(group.enabled);
  useEffect(() => {
    setDraftPermissions(group.permissions);
    setDraftModules(group.modules);
    setDraftEnabled(group.enabled);
  }, [group.enabled, group.modules, group.permissions, group.updated_at]);
  const groupedModules = modules.reduce<Record<string, ModuleCatalogItem[]>>((acc, item) => {
    (acc[item.category] ||= []).push(item);
    return acc;
  }, {});
  const updateSelection = (key: 'permissions' | 'modules', value: string, selected: boolean) => {
    const current = key === 'permissions' ? draftPermissions : draftModules;
    const next = new Set(current);
    if (selected) next.add(value); else next.delete(value);
    if (key === 'permissions') setDraftPermissions([...next].sort());
    else setDraftModules([...next].sort());
  };
  const dirty = (
    draftEnabled !== group.enabled
    || draftPermissions.join('|') !== [...group.permissions].sort().join('|')
    || draftModules.join('|') !== [...group.modules].sort().join('|')
  );

  return (
    <details className={`rounded border ${group.enabled ? 'border-gray-700 bg-gray-950/40' : 'border-gray-800 bg-gray-950/20 opacity-75'}`}>
      <summary className="flex cursor-pointer list-none items-start justify-between gap-4 p-4">
        <span className="min-w-0">
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-white">{group.name}</span>
            {group.system && <span className="rounded border border-blue-700/60 px-1.5 py-0.5 text-[10px] uppercase text-blue-300">built in</span>}
            {!group.enabled && <span className="rounded border border-red-700/60 px-1.5 py-0.5 text-[10px] uppercase text-red-300">disabled</span>}
          </span>
          <span className="mt-1 block text-xs leading-5 text-gray-500">{group.description || 'No purpose statement.'}</span>
        </span>
        <span className="shrink-0 text-right text-[10px] text-gray-500">
          {group.member_count} members<br />{group.modules.length} modules
        </span>
      </summary>
      <div className="grid gap-5 border-t border-gray-800 p-4 xl:grid-cols-[280px_1fr]">
        <div>
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Action permissions</h3>
            <button
              type="button"
              disabled={disabled}
              className={draftEnabled ? 'secondary-action border-green-700 text-green-300' : 'secondary-action border-red-700 text-red-300'}
              onClick={() => setDraftEnabled(value => !value)}
            >
              {draftEnabled ? 'Enabled' : 'Disabled'}
            </button>
          </div>
          <div className="mt-3 grid gap-1">
            {permissions.map(permission => (
              <TogglePermission
                key={permission}
                value={permission}
                disabled={disabled}
                selected={draftPermissions.includes(permission)}
                onChange={next => updateSelection('permissions', permission, next)}
              />
            ))}
          </div>
          {!group.system && (
            <button
              type="button"
              disabled={disabled || group.member_count > 0}
              title={group.member_count > 0 ? 'Remove all members before deleting this group' : undefined}
              className="mt-4 rounded border border-red-800 px-3 py-1.5 text-xs text-red-300 hover:bg-red-950/40 disabled:cursor-not-allowed disabled:opacity-40"
              onClick={onDelete}
            >
              Delete custom group
            </button>
          )}
          <button
            type="button"
            disabled={disabled || !dirty}
            className="primary-action mt-4 w-full disabled:cursor-not-allowed disabled:opacity-40"
            onClick={() => onUpdate({
              permissions: draftPermissions,
              modules: draftModules,
              enabled: draftEnabled,
            })}
          >
            Save group policy
          </button>
        </div>
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Module access</h3>
          <div className="mt-3 grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
            {Object.entries(groupedModules).map(([category, items]) => (
              <fieldset key={category} className="rounded border border-gray-800 p-3">
                <legend className="px-1 text-[10px] font-semibold uppercase tracking-wide text-gray-500">{category}</legend>
                <div className="grid gap-1">
                  {items.map(item => (
                    <label key={item.key} className="flex items-center gap-2 text-xs text-gray-300">
                      <input
                        type="checkbox"
                        disabled={disabled}
                        checked={draftModules.includes(item.key)}
                        onChange={event => updateSelection('modules', item.key, event.target.checked)}
                      />
                      <span>{item.label}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
            ))}
          </div>
        </div>
      </div>
    </details>
  );
}
