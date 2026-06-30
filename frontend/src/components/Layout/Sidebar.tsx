import { NavLink } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authApi, syncApi } from '@/api/client';
import { REFERENCE_BASE_URL } from '@/config/references';
import clsx from 'clsx';
import { GlobalSearch } from '@/components/GlobalSearch';
import { useAppStore } from '@/store';
import { useState } from 'react';
import adversaryGraphIcon from '@/assets/adversarygraph-ai-icon-192.png';
import { useCurrentUser, hasRole } from '@/hooks/useCurrentUser';

const nav = [
  { to: '/discover',      label: 'Discover',      icon: '⌕' },
  { to: '/navigator',     label: 'Navigator',     icon: '⬡' },
  { to: '/apt',           label: 'ATT&CK Group Library', icon: '◈' },
  { to: '/analyze',       label: 'AI Analysis',   icon: '⬢' },
  { to: '/compare',       label: 'Compare',       icon: '⬡' },
  { to: '/sector-intel',  label: 'Sector Intel', icon: '◎' },
  { to: '/asset-surface', label: 'Asset Surface', icon: '▥' },
  { to: '/attack-simulation', label: 'Attack Simulation', icon: '◎' },
  { to: '/evidence-graph', label: 'Evidence Graph', icon: '⟡' },
  { to: '/retrohunt',     label: 'RetroHunt', icon: '⌖' },
  { to: '/knowledge',     label: 'Knowledge Library', icon: '◎' },
  { to: '/ioc-library',   label: 'IOC Library', icon: '▣' },
  { to: '/ioc-investigation', label: 'IOC Investigation', icon: '⌬' },
  { to: '/cve',           label: 'CVE Library', icon: '▨' },
  { to: '/feeds',         label: 'Feeds Management', icon: '≋' },
  { to: '/malware-analysis', label: 'Malware Analysis', icon: '▧' },
  { to: '/virustotal',    label: 'VirusTotal Lookup', icon: '◇' },
  { to: '/report',        label: 'Investigation', icon: '▤' },
  { to: '/operations',    label: 'Operations', icon: '◆' },
  { to: '/pipeline',      label: 'Pipeline', icon: '⇄' },
  { to: '/observability', label: 'Observability', icon: '◌' },
  { to: '/admin',         label: 'Admin Panel', icon: '⚙' },
  { to: '/examples',      label: 'DFIR Examples', icon: '▦' },
  { to: '/troubleshooting', label: 'Troubleshooting', icon: '!' },
];

export function Sidebar() {
  const qc = useQueryClient();
  const { workspaces, saveWorkspace, loadWorkspace, deleteWorkspace } = useAppStore();
  const [showWorkspaces, setShowWorkspaces] = useState(false);
  const { data: user } = useCurrentUser();
  const logout = useMutation({
    mutationFn: authApi.logout,
    onSuccess: async () => {
      await qc.clear();
      window.location.assign('/');
    },
  });
  const { data: syncStatus } = useQuery({
    queryKey: ['sync-status'],
    queryFn: syncApi.status,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  const hasUpdate = syncStatus?.any_updates_needed ?? false;

  return (
    <aside className="flex h-screen min-h-0 w-56 shrink-0 flex-col overflow-hidden border-r border-gray-700 bg-mitre-navy">
      {/* Logo */}
      <div className="shrink-0 border-b border-gray-700 px-5 py-5">
        <div className="flex items-center gap-2">
          <img src={adversaryGraphIcon} alt="" className="h-8 w-8 rounded-lg object-cover" />
          <div>
            <div className="text-sm font-bold text-white tracking-wide">AdversaryGraph</div>
            <div className="text-xs text-gray-400">ATT&CK Intelligence</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-scroll min-h-0 flex-1 space-y-1 overflow-y-auto overscroll-contain px-3 py-4">
        <div className="sticky top-0 z-10 -mx-3 -mt-4 bg-mitre-navy px-3 pb-3 pt-4"><GlobalSearch /></div>
        {nav.filter(item => item.to !== '/admin' || hasRole(user, 'admin')).map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-mitre-accent/20 text-mitre-accent'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
              )
            }
          >
            <span className="text-base">{icon}</span>
            {label}
          </NavLink>
        ))}
        <a
          href={`${REFERENCE_BASE_URL}/`}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-400 hover:text-white hover:bg-gray-700/50 transition-colors"
        >
          <span className="text-base">▤</span>
          Reference Book
        </a>
      </nav>

      {/* Ecosystem links */}
      <div className="sidebar-scroll max-h-[30vh] shrink-0 space-y-1 overflow-y-auto overscroll-contain border-t border-gray-800 px-3 py-3">
        <button onClick={() => setShowWorkspaces(value => !value)} className="w-full flex items-center px-3 py-1.5 rounded-lg text-[11px] text-gray-500 hover:text-gray-300 hover:bg-gray-700/40">
          Workspaces ({workspaces.length})
        </button>
        {showWorkspaces && <div className="rounded border border-gray-700 bg-gray-900 p-2 space-y-1">
          <button onClick={() => saveWorkspace(prompt('Workspace name') ?? '')} className="w-full text-left text-[10px] text-blue-400 px-2 py-1">+ Save current investigation</button>
          {workspaces.map(item => <div key={item.id} className="flex items-center gap-1"><button onClick={() => loadWorkspace(item.id)} className="flex-1 truncate text-left text-[10px] text-gray-400 px-2 py-1">{item.name}</button><button onClick={() => deleteWorkspace(item.id)} className="text-[10px] text-gray-600">×</button></div>)}
        </div>}
        {[
          { href: 'https://1200km.com/threat-matrix/', label: '◈ Web Tool (no Docker)' },
          { href: 'https://1200km.com/cti.html',      label: '↗ CTI Knowledge Base' },
          { href: 'https://1200km.com/adversarygraph/#feedback', label: '↗ Bug / Feature / Feedback' },
          { href: 'https://1200km.com',               label: '↗ 1200km.com' },
        ].map(({ href, label }) => (
          <a
            key={href}
            href={href}
            target="_blank"
            rel="noreferrer"
            className="flex items-center px-3 py-1.5 rounded-lg text-[11px] text-gray-500 hover:text-gray-300 hover:bg-gray-700/40 transition-colors"
          >
            {label}
          </a>
        ))}
      </div>

      {/* Footer — ATT&CK sync status */}
      <div className="shrink-0 border-t border-gray-700 px-4 py-3">
        {hasUpdate ? (
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-amber-400 animate-pulse shrink-0" />
            <NavLink to="/feeds" className="text-[10px] text-amber-400 hover:text-amber-300">ATT&CK update available</NavLink>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-600 shrink-0" />
            <NavLink to="/feeds" className="text-[10px] text-gray-500 hover:text-gray-300">ATT&CK up to date</NavLink>
          </div>
        )}
        <div className="text-[10px] text-gray-600 mt-0.5">AdversaryGraph v5.5.0</div>
        {user?.auth_enabled && (
          <div className="mt-2 flex items-center justify-between gap-2 border-t border-gray-800 pt-2">
            <div className="min-w-0">
              <div className="truncate text-[10px] text-gray-400">{user.name}</div>
              <div className="truncate text-[10px] text-gray-600">{user.roles.join(', ')}</div>
            </div>
            <button className="text-[10px] text-gray-500 hover:text-red-300" onClick={() => logout.mutate()}>
              Logout
            </button>
          </div>
        )}
      </div>
    </aside>
  );
}
