import { NavLink } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authApi, syncApi, type CurrentUser } from '@/api/client';
import { REFERENCE_BASE_URL } from '@/config/references';
import clsx from 'clsx';
import { GlobalSearch } from '@/components/GlobalSearch';
import { useAppStore } from '@/store';
import { useState } from 'react';
import adversaryGraphIcon from '@/assets/adversarygraph-ai-icon-192.png';
import { useCurrentUser, hasPermission } from '@/hooks/useCurrentUser';
import packageMetadata from '../../../package.json';

type NavItem = {
  label: string;
  icon: string;
  permission?: string;
  anyPermission?: string[];
} & (
  | { to: string; href?: never }
  | { href: string; to?: never }
);

type NavSection = {
  id: string;
  label: string;
  items: NavItem[];
};

const navSections: NavSection[] = [
  {
    id: 'workspace',
    label: 'Workspace',
    items: [
      { to: '/discover', label: 'Discover', icon: '⌕' },
    ],
  },
  {
    id: 'intelligence',
    label: 'Intelligence',
    items: [
      { to: '/threat-radar', label: 'Threat Radar', icon: '◉', permission: 'run_analysis' },
      { to: '/reports-research', label: 'Reports / Research', icon: '▤' },
      { to: '/apt', label: 'ATT&CK Group Library', icon: '◈' },
      { to: '/sector-intel', label: 'Sector Intel', icon: '◎' },
      { to: '/knowledge', label: 'Knowledge Library', icon: '◎' },
      { to: '/ioc-library', label: 'IOC Library', icon: '▣' },
      { to: '/cve', label: 'CVE Library', icon: '▨' },
      { to: '/retrohunt', label: 'RetroHunt Signals', icon: '↺' },
    ],
  },
  {
    id: 'analyze-investigate',
    label: 'Analyze & Investigate',
    items: [
      { to: '/analyze', label: 'AI Analysis', icon: '⬢' },
      { to: '/navigator', label: 'Navigator', icon: '⬡' },
      { to: '/compare', label: 'Compare', icon: '⬡' },
      { to: '/ioc-investigation', label: 'IOC Investigation', icon: '⌬', permission: 'run_analysis' },
      { to: '/malware-analysis', label: 'Malware Analysis', icon: '▧', permission: 'run_analysis' },
      { to: '/virustotal', label: 'VirusTotal Lookup', icon: '◇', permission: 'run_analysis' },
      { to: '/asset-surface', label: 'Asset Surface', icon: '▥', permission: 'run_analysis' },
      { to: '/emb3d', label: 'EMB3D', icon: '▧', permission: 'run_analysis' },
      { to: '/evidence-graph', label: 'Evidence Graph', icon: '⟡', permission: 'run_analysis' },
    ],
  },
  {
    id: 'hunt-validate',
    label: 'Hunt & Validate',
    items: [
      { to: '/threat-hunting', label: 'Threat Hunting', icon: '⌖', permission: 'run_analysis' },
      { to: '/query-library', label: 'Query Library', icon: '⌕', permission: 'run_analysis' },
      { to: '/attack-simulation', label: 'Attack Simulation', icon: '◎', permission: 'run_attack_simulation' },
      { to: '/report', label: 'Investigation', icon: '▤', permission: 'run_analysis' },
    ],
  },
  {
    id: 'operations',
    label: 'Operations',
    items: [
      { to: '/operations', label: 'Operations', icon: '◆', permission: 'run_analysis' },
      { to: '/pipeline', label: 'Pipeline', icon: '⇄', permission: 'run_analysis' },
      { to: '/statistics', label: 'Statistics', icon: '▥', permission: 'run_analysis' },
    ],
  },
  {
    id: 'platform',
    label: 'Platform',
    items: [
      { to: '/feeds', label: 'Feeds Management', icon: '≋', permission: 'manage_feeds' },
      { to: '/observability', label: 'Observability', icon: '◌', permission: 'view_audit' },
      { to: '/admin', label: 'Admin Panel', icon: '⚙', anyPermission: ['manage_users', 'manage_auth', 'view_audit'] },
    ],
  },
  {
    id: 'learn-support',
    label: 'Learn & Support',
    items: [
      { to: '/examples', label: 'DFIR Examples', icon: '▦' },
      { href: `${REFERENCE_BASE_URL}/`, label: 'Reference Book', icon: '▤' },
      { to: '/help', label: 'Help / Local Guide', icon: '?' },
      { to: '/troubleshooting', label: 'Troubleshooting', icon: '!' },
    ],
  },
];

function canViewNavItem(user: CurrentUser | undefined, item: NavItem): boolean {
  return (
    (!item.permission || hasPermission(user, item.permission))
    && (!item.anyPermission?.length || item.anyPermission.some(permission => hasPermission(user, permission)))
  );
}

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
  const visibleSections = navSections
    .map(section => ({ ...section, items: section.items.filter(item => canViewNavItem(user, item)) }))
    .filter(section => section.items.length > 0);

  return (
    <aside aria-label="Application navigation" className="app-sidebar flex min-h-0 w-56 shrink-0 flex-col overflow-hidden border-r border-gray-700 bg-mitre-navy">
      {/* Logo */}
      <div className="shrink-0 border-b border-gray-700 px-5 py-4">
        <div className="flex items-center gap-2">
          <img src={adversaryGraphIcon} alt="" className="h-8 w-8 rounded-lg object-cover" />
          <div>
            <div className="text-sm font-bold text-white tracking-wide">AdversaryGraph</div>
            <div className="text-xs text-gray-400">ATT&CK Intelligence</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav aria-label="Primary" data-testid="sidebar-primary-nav" className="sidebar-scroll min-h-0 flex-1 overflow-y-auto overscroll-contain px-3 py-2">
        <div className="sticky top-0 z-10 -mx-3 -mt-2 bg-mitre-navy px-3 pb-2 pt-2"><GlobalSearch /></div>
        <div className="space-y-3">
          {visibleSections.map(section => (
            <section
              key={section.id}
              aria-labelledby={`sidebar-section-${section.id}`}
              data-testid={`sidebar-section-${section.id}`}
            >
              <h2
                id={`sidebar-section-${section.id}`}
                className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500"
              >
                {section.label}
              </h2>
              <ul className="list-none space-y-1 p-0">
                {section.items.map(item => (
                  <li key={item.to ?? item.href}>
                    {item.to ? (
                      <NavLink
                        to={item.to}
                        className={({ isActive }) =>
                          clsx(
                            'flex min-w-0 items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                            isActive
                              ? 'bg-mitre-accent/20 text-mitre-accent'
                              : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
                          )
                        }
                        title={item.label}
                      >
                        <span className="shrink-0 text-base">{item.icon}</span>
                        <span className="min-w-0 truncate">{item.label}</span>
                      </NavLink>
                    ) : (
                      <a
                        href={item.href}
                        target="_blank"
                        rel="noreferrer"
                        className="flex min-w-0 items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-gray-400 transition-colors hover:bg-gray-700/50 hover:text-white"
                        title={item.label}
                      >
                        <span className="shrink-0 text-base">{item.icon}</span>
                        <span className="min-w-0 truncate">{item.label}</span>
                      </a>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </nav>

      {/* Ecosystem links */}
      <div className="sidebar-scroll max-h-[22vh] shrink-0 space-y-1 overflow-y-auto overscroll-contain border-t border-gray-800 px-3 py-3">
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
            className="flex min-w-0 items-center rounded-lg px-3 py-1.5 text-[11px] text-gray-500 transition-colors hover:bg-gray-700/40 hover:text-gray-300"
            title={label.replace(/^[^A-Za-z0-9]+/, '')}
          >
            <span className="min-w-0 truncate">{label}</span>
          </a>
        ))}
      </div>

      {/* Footer — ATT&CK sync status */}
      <div className="shrink-0 border-t border-gray-700 px-4 py-3">
        {hasUpdate ? (
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-amber-400 animate-pulse shrink-0" />
            {hasPermission(user, 'manage_feeds') ? <NavLink to="/feeds" className="text-[10px] text-amber-400 hover:text-amber-300">ATT&CK update available</NavLink> : <span className="text-[10px] text-amber-400">ATT&CK update available</span>}
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-600 shrink-0" />
            {hasPermission(user, 'manage_feeds') ? <NavLink to="/feeds" className="text-[10px] text-gray-500 hover:text-gray-300">ATT&CK up to date</NavLink> : <span className="text-[10px] text-gray-500">ATT&CK up to date</span>}
          </div>
        )}
        <div className="text-[10px] text-gray-600 mt-0.5">AdversaryGraph v{packageMetadata.version}</div>
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
