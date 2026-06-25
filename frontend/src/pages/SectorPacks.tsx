import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { sectorPacksApi, SectorPack } from '../api/client';

const CONFIDENCE_COLORS: Record<string, string> = {
  High: '#ef4444',
  Medium: '#f59e0b',
  Low: '#6b7280',
  Unknown: '#374151',
};

const TABS = [
  { key: 'overview', label: 'Overview' },
  { key: 'intel', label: 'Intelligence' },
  { key: 'ttps', label: 'TTPs & Detection' },
  { key: 'psirt', label: 'PSIRT & Vuln' },
  { key: 'actions', label: 'Actions' },
] as const;

type TabKey = typeof TABS[number]['key'];

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '1px 7px', borderRadius: 4,
      fontSize: 11, fontWeight: 700, background: color + '22',
      color, border: `1px solid ${color}55`, marginRight: 4,
    }}>
      {label}
    </span>
  );
}

function ListSection({ title, items }: { title: string; items: string[] }) {
  if (!items || items.length === 0) return null;
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontWeight: 600, color: '#9ca3af', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
        {title}
      </div>
      <ul style={{ margin: 0, paddingLeft: 18 }}>
        {items.map((item, i) => (
          <li key={i} style={{ marginBottom: 3, fontSize: 13, color: '#e5e7eb' }}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function TextSection({ title, text }: { title: string; text: string }) {
  if (!text) return null;
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontWeight: 600, color: '#9ca3af', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
        {title}
      </div>
      <p style={{ margin: 0, fontSize: 13, color: '#e5e7eb', lineHeight: 1.6 }}>{text}</p>
    </div>
  );
}

function PackDetail({ pack, onClose }: { pack: SectorPack; onClose: () => void }) {
  const [tab, setTab] = useState<TabKey>('overview');
  const confColor = CONFIDENCE_COLORS[pack.confidence_level] ?? '#6b7280';

  function exportMarkdown() {
    const lines: string[] = [
      `# ${pack.sector_name} — NVIDIA Sector Intelligence Pack`,
      ``,
      `**Confidence:** ${pack.confidence_level}  |  **Source:** ${pack.pack_source}  |  **ID:** \`${pack.sector_id}\``,
      ``,
      `## Summary`,
      pack.sector_summary,
      ``,
      `## Relevance to NVIDIA`,
      pack.relevance_to_nvidia,
      ``,
      `## NVIDIA Products`,
      ...pack.relevant_nvidia_products.map(p => `- ${p}`),
      ``,
      `## Crown Jewel Assets`,
      ...pack.crown_jewel_assets.map(p => `- ${p}`),
      ``,
      `## Likely Threat Actors`,
      ...pack.likely_threat_actors.map(p => `- ${p}`),
      ``,
      `## Adversary Motivations`,
      ...pack.adversary_motivations.map(p => `- ${p}`),
      ``,
      `## Common Attack Surfaces`,
      ...pack.common_attack_surfaces.map(p => `- ${p}`),
      ``,
      `## Likely Attack Paths`,
      ...pack.likely_attack_paths.map(p => `- ${p}`),
      ``,
      `## Priority Intelligence Requirements (PIRs)`,
      ...pack.priority_intelligence_requirements.map(p => `- ${p}`),
      ``,
      `## Intelligence Requirements`,
      ...pack.intelligence_requirements.map(p => `- ${p}`),
      ``,
      `## Early Warning Indicators`,
      ...pack.early_warning_indicators.map(p => `- ${p}`),
      ``,
      `## Relevant IOC Types`,
      ...pack.relevant_ioc_types.map(p => `- ${p}`),
      ``,
      `## TTP Categories`,
      ...pack.relevant_ttp_categories.map(p => `- ${p}`),
      ``,
      `## MITRE ATT&CK Focus`,
      ...pack.mitre_attack_focus.map(p => `- ${p}`),
      ``,
      `## Vulnerability Intelligence Focus`,
      ...pack.vulnerability_intelligence_focus.map(p => `- ${p}`),
      ``,
      `## Supply Chain Risk Focus`,
      ...pack.supply_chain_risk_focus.map(p => `- ${p}`),
      ``,
      `## Product Security (PSIRT) Relevance`,
      pack.product_security_relevance,
      ``,
      `## Telemetry Requirements`,
      ...pack.telemetry_requirements.map(p => `- ${p}`),
      ``,
      `## Hunting Opportunities`,
      ...pack.hunting_opportunities.map(p => `- ${p}`),
      ``,
      `## Detection Engineering Opportunities`,
      ...pack.detection_engineering_opportunities.map(p => `- ${p}`),
      ``,
      `## Mitigation Recommendations`,
      ...pack.mitigation_recommendations.map(p => `- ${p}`),
      ``,
      `## Engineering Follow-up Actions`,
      ...pack.engineering_follow_up_actions.map(p => `- ${p}`),
      ``,
      `## Customer Risk Considerations`,
      ...pack.customer_risk_considerations.map(p => `- ${p}`),
      ``,
      `## Executive Summary Points`,
      ...pack.executive_summary_points.map(p => `- ${p}`),
      ``,
      `## Analyst Notes`,
      pack.analyst_notes,
      ``,
      `## Source Requirements`,
      ...pack.source_requirements.map(p => `- ${p}`),
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${pack.sector_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    }} onClick={onClose}>
      <div style={{
        background: '#1a1f2e', border: '1px solid #374151', borderRadius: 8,
        width: '90vw', maxWidth: 900, maxHeight: '88vh',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }} onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div style={{
          padding: '16px 20px', borderBottom: '1px solid #374151',
          display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0,
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <Badge label={pack.confidence_level} color={confColor} />
              <span style={{ fontSize: 11, color: '#6b7280' }}>{pack.sector_id}</span>
            </div>
            <h2 style={{ margin: 0, fontSize: 18, color: '#f3f4f6' }}>{pack.sector_name}</h2>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={exportMarkdown}
              style={{
                padding: '5px 12px', background: '#1e3a5f', color: '#60a5fa',
                border: '1px solid #1d4ed8', borderRadius: 4, cursor: 'pointer', fontSize: 12,
              }}
            >
              Export MD
            </button>
            <button
              onClick={onClose}
              style={{
                padding: '5px 12px', background: '#374151', color: '#9ca3af',
                border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 12,
              }}
            >
              Close
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div style={{
          display: 'flex', borderBottom: '1px solid #374151',
          background: '#111827', flexShrink: 0,
        }}>
          {TABS.map(t => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              style={{
                padding: '8px 16px', background: 'none', border: 'none',
                borderBottom: tab === t.key ? '2px solid #3b82f6' : '2px solid transparent',
                color: tab === t.key ? '#60a5fa' : '#6b7280',
                cursor: 'pointer', fontSize: 13, fontWeight: tab === t.key ? 600 : 400,
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>
          {tab === 'overview' && (
            <>
              <TextSection title="Sector Summary" text={pack.sector_summary} />
              <TextSection title="Relevance to NVIDIA" text={pack.relevance_to_nvidia} />
              <ListSection title="Relevant NVIDIA Products" items={pack.relevant_nvidia_products} />
              <ListSection title="Crown Jewel Assets" items={pack.crown_jewel_assets} />
              <ListSection title="Likely Threat Actors" items={pack.likely_threat_actors} />
              <ListSection title="Adversary Motivations" items={pack.adversary_motivations} />
              <ListSection title="Executive Summary Points" items={pack.executive_summary_points} />
            </>
          )}
          {tab === 'intel' && (
            <>
              <ListSection title="Priority Intelligence Requirements (PIRs)" items={pack.priority_intelligence_requirements} />
              <ListSection title="Intelligence Requirements" items={pack.intelligence_requirements} />
              <ListSection title="Early Warning Indicators" items={pack.early_warning_indicators} />
              <ListSection title="Relevant IOC Types" items={pack.relevant_ioc_types} />
              <ListSection title="Common Attack Surfaces" items={pack.common_attack_surfaces} />
              <ListSection title="Likely Attack Paths" items={pack.likely_attack_paths} />
              <ListSection title="Customer Risk Considerations" items={pack.customer_risk_considerations} />
            </>
          )}
          {tab === 'ttps' && (
            <>
              <ListSection title="TTP Categories" items={pack.relevant_ttp_categories} />
              <ListSection title="MITRE ATT&CK Focus" items={pack.mitre_attack_focus} />
              <ListSection title="Hunting Opportunities" items={pack.hunting_opportunities} />
              <ListSection title="Detection Engineering Opportunities" items={pack.detection_engineering_opportunities} />
              <ListSection title="Telemetry Requirements" items={pack.telemetry_requirements} />
            </>
          )}
          {tab === 'psirt' && (
            <>
              <TextSection title="Product Security (PSIRT) Relevance" text={pack.product_security_relevance} />
              <ListSection title="Vulnerability Intelligence Focus" items={pack.vulnerability_intelligence_focus} />
              <ListSection title="Supply Chain Risk Focus" items={pack.supply_chain_risk_focus} />
              <ListSection title="Source Requirements" items={pack.source_requirements} />
              <TextSection title="Analyst Notes" text={pack.analyst_notes} />
            </>
          )}
          {tab === 'actions' && (
            <>
              <ListSection title="Mitigation Recommendations" items={pack.mitigation_recommendations} />
              <ListSection title="Engineering Follow-up Actions" items={pack.engineering_follow_up_actions} />
              <ListSection title="Customer Risk Considerations" items={pack.customer_risk_considerations} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function PackCard({ pack, onClick }: { pack: SectorPack; onClick: () => void }) {
  const confColor = CONFIDENCE_COLORS[pack.confidence_level] ?? '#6b7280';
  return (
    <div
      onClick={onClick}
      style={{
        background: '#111827', border: '1px solid #374151', borderRadius: 8,
        padding: 16, cursor: 'pointer', transition: 'border-color 0.15s',
      }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = '#3b82f6')}
      onMouseLeave={e => (e.currentTarget.style.borderColor = '#374151')}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
        <span style={{ fontWeight: 600, color: '#f3f4f6', fontSize: 14 }}>{pack.sector_name}</span>
        <Badge label={pack.confidence_level} color={confColor} />
      </div>
      <p style={{ margin: '0 0 10px', fontSize: 12, color: '#9ca3af', lineHeight: 1.5 }}>
        {pack.sector_summary.slice(0, 130)}{pack.sector_summary.length > 130 ? '…' : ''}
      </p>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
        {pack.mitre_attack_focus.slice(0, 3).map(t => (
          <span key={t} style={{
            fontSize: 10, padding: '1px 6px', borderRadius: 3,
            background: '#1e293b', color: '#64748b', border: '1px solid #334155',
          }}>{t.split(' ')[0]}</span>
        ))}
        {pack.mitre_attack_focus.length > 3 && (
          <span style={{ fontSize: 10, color: '#4b5563' }}>+{pack.mitre_attack_focus.length - 3} more</span>
        )}
      </div>
    </div>
  );
}

export default function SectorPacks() {
  const [selected, setSelected] = useState<SectorPack | null>(null);
  const [filterConf, setFilterConf] = useState('');
  const [search, setSearch] = useState('');

  const { data: packs = [], isLoading, error } = useQuery({
    queryKey: ['sector-packs'],
    queryFn: () => sectorPacksApi.list({ pack_source: 'nvidia' }),
  });

  const filtered = packs.filter(p => {
    if (filterConf && p.confidence_level !== filterConf) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        p.sector_name.toLowerCase().includes(q) ||
        p.sector_summary.toLowerCase().includes(q) ||
        p.relevant_nvidia_products.some(x => x.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <div style={{ padding: '24px', maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ margin: '0 0 4px', fontSize: 22, color: '#f3f4f6' }}>NVIDIA Sector Intelligence Packs</h1>
        <p style={{ margin: 0, color: '#6b7280', fontSize: 13 }}>
          Structured threat intelligence for 15 NVIDIA-relevant sectors. All intelligence is based on public
          information and analytic assessments — no proprietary data.
        </p>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap' }}>
        <input
          placeholder="Search sectors, products..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            flex: 1, minWidth: 200, padding: '7px 12px',
            background: '#111827', border: '1px solid #374151', borderRadius: 6,
            color: '#f3f4f6', fontSize: 13, outline: 'none',
          }}
        />
        <select
          value={filterConf}
          onChange={e => setFilterConf(e.target.value)}
          style={{
            padding: '7px 12px', background: '#111827', border: '1px solid #374151',
            borderRadius: 6, color: '#f3f4f6', fontSize: 13, outline: 'none',
          }}
        >
          <option value="">All confidence levels</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Unknown">Unknown</option>
        </select>
        <div style={{ display: 'flex', alignItems: 'center', color: '#6b7280', fontSize: 12 }}>
          {filtered.length} / {packs.length} sectors
        </div>
      </div>

      {isLoading && (
        <div style={{ color: '#6b7280', textAlign: 'center', padding: 48 }}>Loading sector packs…</div>
      )}
      {error && (
        <div style={{ color: '#ef4444', padding: 16 }}>
          Failed to load sector packs: {String(error)}
        </div>
      )}

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
        gap: 14,
      }}>
        {filtered.map(pack => (
          <PackCard key={pack.sector_id} pack={pack} onClick={() => setSelected(pack)} />
        ))}
      </div>

      {filtered.length === 0 && !isLoading && (
        <div style={{ color: '#6b7280', textAlign: 'center', padding: 48 }}>
          No sector packs match your filters.
        </div>
      )}

      {selected && (
        <PackDetail pack={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
