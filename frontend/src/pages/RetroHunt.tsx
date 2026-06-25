import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { retroHuntApi, RetroHuntSignal } from '../api/client';
import { useNavigate } from 'react-router-dom';

// ── Constants ─────────────────────────────────────────────────────────────────

const SOURCE_LABELS: Record<string, string> = {
  nvd: 'NVD',
  cisa_kev: 'CISA KEV',
  github_advisory: 'GitHub',
  exploitdb: 'Exploit-DB',
};

const SOURCE_COLORS: Record<string, string> = {
  nvd: '#3b82f6',
  cisa_kev: '#ef4444',
  github_advisory: '#8b5cf6',
  exploitdb: '#f59e0b',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ef4444',
  medium: '#f59e0b',
  low: '#6b7280',
  unknown: '#374151',
};

const SIGNAL_TYPE_ICONS: Record<string, string> = {
  cve: '⚠',
  exploit: '⚡',
  advisory: '📋',
  report: '📄',
};

const SECTOR_LABELS: Record<string, string> = {
  nvidia_firmware_drivers: 'Firmware & Drivers',
  nvidia_accelerated_computing: 'CUDA / Accelerated',
  nvidia_ai_data_centers: 'AI Data Centers',
  nvidia_ai_networking_fabric: 'AI Networking',
  nvidia_dpu_smartnic: 'DPU / BlueField',
  nvidia_cloud_hyperscale: 'Cloud / Hyperscale',
  nvidia_semiconductor_supply_chain: 'Supply Chain',
  nvidia_autonomous_vehicles: 'Autonomous Vehicles',
  nvidia_healthcare_ai: 'Healthcare AI',
  nvidia_telecom_5g_edge: 'Telecom / 5G',
  nvidia_enterprise_ai: 'Enterprise AI',
  nvidia_gaming_rtx: 'Gaming / RTX',
  nvidia_hpc_supercomputing: 'HPC',
  nvidia_robotics: 'Robotics',
  nvidia_manufacturing_supply_chain: 'Manufacturing',
};

// ── Small components ──────────────────────────────────────────────────────────

function Badge({ label, color, small }: { label: string; color: string; small?: boolean }) {
  return (
    <span style={{
      display: 'inline-block',
      padding: small ? '1px 5px' : '2px 7px',
      borderRadius: 4,
      fontSize: small ? 10 : 11,
      fontWeight: 700,
      background: color + '22',
      color,
      border: `1px solid ${color}44`,
      whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  );
}

function StatCard({ label, value, sub }: { label: string; value: number | string; sub?: string }) {
  return (
    <div style={{
      background: '#111827', border: '1px solid #1f2937',
      borderRadius: 8, padding: '12px 16px',
    }}>
      <div style={{ fontSize: 22, fontWeight: 700, color: '#f3f4f6' }}>{value}</div>
      <div style={{ fontSize: 12, color: '#6b7280', marginTop: 2 }}>{label}</div>
      {sub && <div style={{ fontSize: 10, color: '#374151', marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

// ── Signal detail modal ───────────────────────────────────────────────────────

function SignalDetail({ signal, onClose }: { signal: RetroHuntSignal; onClose: () => void }) {
  const navigate = useNavigate();
  const sevColor = SEVERITY_COLORS[signal.severity] ?? '#6b7280';
  const srcColor = SOURCE_COLORS[signal.source] ?? '#6b7280';

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}
      onClick={onClose}
    >
      <div
        style={{ background: '#1a1f2e', border: '1px solid #374151', borderRadius: 8, width: '88vw', maxWidth: 780, maxHeight: '86vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1f2937', display: 'flex', gap: 10, alignItems: 'flex-start' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
              <Badge label={SOURCE_LABELS[signal.source] ?? signal.source} color={srcColor} />
              <Badge label={signal.severity.toUpperCase()} color={sevColor} />
              {signal.cvss_score != null && (
                <Badge label={`CVSS ${signal.cvss_score.toFixed(1)}`} color={sevColor} small />
              )}
              <span style={{ fontSize: 10, color: '#4b5563', alignSelf: 'center' }}>{signal.signal_type}</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 600, color: '#f3f4f6', lineHeight: 1.4 }}>{signal.title}</div>
          </div>
          <button onClick={onClose} style={{ flexShrink: 0, background: '#374151', border: 'none', color: '#9ca3af', borderRadius: 4, padding: '4px 10px', cursor: 'pointer', fontSize: 12 }}>
            Close
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 18 }}>
          {signal.body && (
            <p style={{ margin: '0 0 16px', fontSize: 13, color: '#d1d5db', lineHeight: 1.6 }}>{signal.body}</p>
          )}

          {signal.cve_ids.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>CVE IDs</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {signal.cve_ids.map(cve => (
                  <button
                    key={cve}
                    onClick={() => { onClose(); navigate(`/ioc-investigation?q=${encodeURIComponent(cve)}`); }}
                    style={{ background: '#1e3a5f', color: '#60a5fa', border: '1px solid #1d4ed8', borderRadius: 4, padding: '3px 8px', fontSize: 12, cursor: 'pointer', fontFamily: 'monospace' }}
                  >
                    {cve}
                  </button>
                ))}
              </div>
            </div>
          )}

          {signal.sector_tags.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>Sector Tags</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {signal.sector_tags.map(s => (
                  <Badge key={s} label={SECTOR_LABELS[s] ?? s} color="#8b5cf6" small />
                ))}
              </div>
            </div>
          )}

          {signal.tech_tags.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>Tech Tags</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {signal.tech_tags.map(t => (
                  <Badge key={t} label={t.replace(/_/g, ' ')} color="#10b981" small />
                ))}
              </div>
            </div>
          )}

          {signal.product_tags.filter(Boolean).length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>Affected Products</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {signal.product_tags.filter(Boolean).map((p, i) => (
                  <span key={i} style={{ fontSize: 11, color: '#9ca3af', background: '#1f2937', padding: '2px 6px', borderRadius: 3, border: '1px solid #374151' }}>{p}</span>
                ))}
              </div>
            </div>
          )}

          {signal.url && (
            <div style={{ marginTop: 16 }}>
              <a href={signal.url} target="_blank" rel="noreferrer" style={{ color: '#60a5fa', fontSize: 12 }}>
                View source →
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Signal row ────────────────────────────────────────────────────────────────

function SignalRow({ signal, onClick }: { signal: RetroHuntSignal; onClick: () => void }) {
  const sevColor = SEVERITY_COLORS[signal.severity] ?? '#6b7280';
  const srcColor = SOURCE_COLORS[signal.source] ?? '#6b7280';
  const date = signal.published_at ? new Date(signal.published_at).toLocaleDateString() : '—';
  const icon = SIGNAL_TYPE_ICONS[signal.signal_type] ?? '•';

  return (
    <div
      onClick={onClick}
      style={{
        display: 'grid', gridTemplateColumns: '28px 1fr auto',
        gap: 10, padding: '10px 14px', cursor: 'pointer',
        borderBottom: '1px solid #111827', alignItems: 'start',
        transition: 'background 0.1s',
      }}
      onMouseEnter={e => (e.currentTarget.style.background = '#0f172a')}
      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
    >
      <div style={{ fontSize: 16, color: sevColor, paddingTop: 2 }}>{icon}</div>
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 13, color: '#e5e7eb', fontWeight: 500, marginBottom: 4, lineHeight: 1.4 }}>
          {signal.title}
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
          <Badge label={SOURCE_LABELS[signal.source] ?? signal.source} color={srcColor} small />
          <Badge label={signal.severity} color={sevColor} small />
          {signal.cvss_score != null && (
            <span style={{ fontSize: 10, color: '#6b7280' }}>CVSS {signal.cvss_score.toFixed(1)}</span>
          )}
          {signal.cve_ids.slice(0, 2).map(cve => (
            <span key={cve} style={{ fontSize: 10, color: '#3b82f6', fontFamily: 'monospace' }}>{cve}</span>
          ))}
          {signal.sector_tags.slice(0, 2).map(s => (
            <span key={s} style={{ fontSize: 10, color: '#8b5cf6' }}>{SECTOR_LABELS[s] ?? s}</span>
          ))}
        </div>
      </div>
      <div style={{ fontSize: 11, color: '#4b5563', whiteSpace: 'nowrap', paddingTop: 2 }}>{date}</div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function RetroHunt() {
  const qc = useQueryClient();

  const [q, setQ] = useState('');
  const [source, setSource] = useState('');
  const [severity, setSeverity] = useState('');
  const [sector, setSector] = useState('');
  const [days, setDays] = useState(30);
  const [selected, setSelected] = useState<RetroHuntSignal | null>(null);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [collectDays, setCollectDays] = useState(30);

  const statsQuery = useQuery({
    queryKey: ['retrohunt-stats', days],
    queryFn: () => retroHuntApi.stats(days),
    staleTime: 60_000,
  });

  const signalsQuery = useQuery({
    queryKey: ['retrohunt-signals', q, source, severity, sector, days],
    queryFn: () => retroHuntApi.signals({ q: q || undefined, source: source || undefined, severity: severity || undefined, sector: sector || undefined, days, limit: 200 }),
    staleTime: 60_000,
  });

  const collectMutation = useMutation({
    mutationFn: () => retroHuntApi.collect(collectDays),
    onSuccess: data => {
      setTaskId(data.task_id);
    },
  });

  // Poll task status until done
  const taskQuery = useQuery({
    queryKey: ['retrohunt-task', taskId],
    queryFn: () => retroHuntApi.taskStatus(taskId!),
    enabled: !!taskId,
    refetchInterval: data => {
      if (!data) return 3000;
      const status = (data as any)?.status;
      return (status === 'SUCCESS' || status === 'FAILURE') ? false : 3000;
    },
  });

  // Refresh signals when task completes
  useEffect(() => {
    const status = (taskQuery.data as any)?.status;
    if (status === 'SUCCESS') {
      qc.invalidateQueries({ queryKey: ['retrohunt-signals'] });
      qc.invalidateQueries({ queryKey: ['retrohunt-stats'] });
    }
  }, [(taskQuery.data as any)?.status]);

  const stats = statsQuery.data;
  const signals = signalsQuery.data ?? [];
  const taskStatus = (taskQuery.data as any)?.status;
  const taskResult = (taskQuery.data as any)?.result;
  const isCollecting = collectMutation.isPending || (taskId && taskStatus && taskStatus !== 'SUCCESS' && taskStatus !== 'FAILURE');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid #1f2937', flexShrink: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div>
            <h1 style={{ margin: 0, fontSize: 18, color: '#f3f4f6' }}>RetroHunt</h1>
            <p style={{ margin: '2px 0 0', fontSize: 12, color: '#6b7280' }}>
              CVE intelligence, known exploits, and security advisories — filtered for NVIDIA-relevant signals
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <select
              value={collectDays}
              onChange={e => setCollectDays(Number(e.target.value))}
              style={{ padding: '5px 8px', background: '#111827', border: '1px solid #374151', borderRadius: 5, color: '#9ca3af', fontSize: 12 }}
            >
              <option value={7}>Last 7 days</option>
              <option value={14}>Last 14 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </select>
            <button
              onClick={() => collectMutation.mutate()}
              disabled={!!isCollecting}
              style={{
                padding: '6px 14px', borderRadius: 5, border: 'none', cursor: isCollecting ? 'not-allowed' : 'pointer',
                background: isCollecting ? '#1f2937' : '#1d4ed8', color: isCollecting ? '#6b7280' : '#fff',
                fontSize: 12, fontWeight: 600,
              }}
            >
              {isCollecting ? `Collecting… (${taskStatus ?? '…'})` : 'Collect signals'}
            </button>
          </div>
        </div>

        {/* Task result feedback */}
        {taskStatus === 'SUCCESS' && taskResult && (
          <div style={{ background: '#052e16', border: '1px solid #14532d', borderRadius: 5, padding: '6px 12px', fontSize: 11, color: '#86efac', marginBottom: 8 }}>
            Collection complete — {taskResult.total_inserted} new signals inserted.{' '}
            {taskResult.results.map((r: any) => `${r.source}: +${r.inserted}`).join(' · ')}
          </div>
        )}
        {taskStatus === 'FAILURE' && (
          <div style={{ background: '#450a0a', border: '1px solid #7f1d1d', borderRadius: 5, padding: '6px 12px', fontSize: 11, color: '#fca5a5', marginBottom: 8 }}>
            Collection failed. Check worker logs.
          </div>
        )}

        {/* Stats row */}
        {stats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(120px, 1fr))', gap: 8, marginBottom: 12 }}>
            <StatCard label="Total signals" value={stats.total} />
            {Object.entries(stats.by_source).map(([src, count]) => (
              <StatCard key={src} label={SOURCE_LABELS[src] ?? src} value={count} />
            ))}
            {Object.entries(stats.by_severity).filter(([s]) => s !== 'unknown').map(([sev, count]) => (
              <StatCard key={sev} label={sev} value={count} />
            ))}
          </div>
        )}

        {/* Filters */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            placeholder="Search title / body / CVE…"
            value={q}
            onChange={e => setQ(e.target.value)}
            style={{
              flex: 1, minWidth: 200, padding: '6px 10px',
              background: '#111827', border: '1px solid #374151',
              borderRadius: 5, color: '#f3f4f6', fontSize: 13, outline: 'none',
            }}
          />
          <select value={source} onChange={e => setSource(e.target.value)}
            style={{ padding: '6px 8px', background: '#111827', border: '1px solid #374151', borderRadius: 5, color: '#d1d5db', fontSize: 12 }}>
            <option value="">All sources</option>
            <option value="nvd">NVD</option>
            <option value="cisa_kev">CISA KEV</option>
            <option value="github_advisory">GitHub Advisory</option>
            <option value="exploitdb">Exploit-DB</option>
          </select>
          <select value={severity} onChange={e => setSeverity(e.target.value)}
            style={{ padding: '6px 8px', background: '#111827', border: '1px solid #374151', borderRadius: 5, color: '#d1d5db', fontSize: 12 }}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={sector} onChange={e => setSector(e.target.value)}
            style={{ padding: '6px 8px', background: '#111827', border: '1px solid #374151', borderRadius: 5, color: '#d1d5db', fontSize: 12 }}>
            <option value="">All sectors</option>
            {Object.entries(SECTOR_LABELS).map(([id, label]) => (
              <option key={id} value={id}>{label}</option>
            ))}
          </select>
          <select value={String(days)} onChange={e => setDays(Number(e.target.value))}
            style={{ padding: '6px 8px', background: '#111827', border: '1px solid #374151', borderRadius: 5, color: '#d1d5db', fontSize: 12 }}>
            <option value="7">7 days</option>
            <option value="14">14 days</option>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year</option>
          </select>
          <span style={{ fontSize: 11, color: '#4b5563', alignSelf: 'center' }}>
            {signals.length} signals
          </span>
        </div>
      </div>

      {/* Signal list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {signalsQuery.isLoading && (
          <div style={{ padding: 40, textAlign: 'center', color: '#6b7280' }}>Loading signals…</div>
        )}
        {!signalsQuery.isLoading && signals.length === 0 && (
          <div style={{ padding: 40, textAlign: 'center', color: '#6b7280' }}>
            No signals found.{' '}
            <button onClick={() => collectMutation.mutate()} style={{ color: '#60a5fa', background: 'none', border: 'none', cursor: 'pointer', fontSize: 13 }}>
              Run collection to populate.
            </button>
          </div>
        )}
        {signals.map(signal => (
          <SignalRow key={signal.id} signal={signal} onClick={() => setSelected(signal)} />
        ))}
      </div>

      {selected && <SignalDetail signal={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
