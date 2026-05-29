import { NavLink } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { syncApi } from '@/api/client';
import clsx from 'clsx';

const nav = [
  { to: '/navigator', label: 'Navigator', icon: '⬡' },
  { to: '/apt',       label: 'APT Library', icon: '◈' },
  { to: '/analyze',   label: 'AI Analysis', icon: '⬢' },
  { to: '/compare',   label: 'Compare', icon: '⬡' },
];

export function Sidebar() {
  const { data: syncStatus } = useQuery({
    queryKey: ['sync-status'],
    queryFn: syncApi.status,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  const hasUpdate = syncStatus?.any_updates_needed ?? false;

  return (
    <aside className="flex flex-col w-56 bg-mitre-navy border-r border-gray-700 shrink-0">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <span className="text-mitre-accent text-2xl font-bold">⬡</span>
          <div>
            <div className="text-sm font-bold text-white tracking-wide">ThreatMapper</div>
            <div className="text-xs text-gray-400">ATT&CK Intelligence</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {nav.map(({ to, label, icon }) => (
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
      </nav>

      {/* Footer — ATT&CK sync status */}
      <div className="px-4 py-3 border-t border-gray-700">
        {hasUpdate ? (
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-amber-400 animate-pulse shrink-0" />
            <span className="text-[10px] text-amber-400">ATT&CK update available</span>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-600 shrink-0" />
            <span className="text-[10px] text-gray-500">ATT&CK up to date</span>
          </div>
        )}
        <div className="text-[10px] text-gray-600 mt-0.5">ThreatMapper v0.2</div>
      </div>
    </aside>
  );
}
