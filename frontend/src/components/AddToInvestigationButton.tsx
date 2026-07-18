import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { operationsApi, type Investigation } from '@/api/client';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';

type InvestigationPayload = {
  label: string;
  description?: string;
  domain: string;
  techniqueIds?: string[];
  actorIds?: string[];
  reportIds?: string[];
  evidenceNodes?: Array<Record<string, unknown>>;
  evidenceEdges?: Array<Record<string, unknown>>;
  timelineEvent?: string;
};

type InvestigationBody = Omit<Investigation, 'id' | 'created_at' | 'updated_at'>;

export function AddToInvestigationButton({
  payload,
  className = 'secondary-action text-xs',
  disabled = false,
}: {
  payload: InvestigationPayload;
  className?: string;
  disabled?: boolean;
}) {
  const queryClient = useQueryClient();
  const canManage = useHasPermission('manage_intel');
  const canRunAnalysis = useHasPermission('run_analysis');
  const canAdd = canManage && canRunAnalysis;
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const [open, setOpen] = useState(false);
  const [selectedId, setSelectedId] = useState('');
  const [message, setMessage] = useState('');
  const [menuPosition, setMenuPosition] = useState({ top: 0, left: 0, width: 320 });
  const { data: investigations = [], isLoading } = useQuery({
    queryKey: ['operations-investigations'],
    queryFn: operationsApi.investigations,
    enabled: open && canAdd,
  });

  const selected = useMemo(
    () => investigations.find(item => item.id === selectedId) ?? investigations[0],
    [investigations, selectedId],
  );

  const addMutation = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error('Choose an investigation first.');
      const body = mergeInvestigation(selected, payload);
      return operationsApi.updateInvestigation(selected.id, body);
    },
    onSuccess: row => {
      setMessage(`Added to ${row.name}`);
      queryClient.invalidateQueries({ queryKey: ['operations-investigations'] });
      setTimeout(() => setOpen(false), 650);
    },
    onError: error => {
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const updatePosition = () => {
    const rect = buttonRef.current?.getBoundingClientRect();
    if (!rect) return;
    const width = Math.min(360, Math.max(1, window.innerWidth - 24));
    const left = Math.min(Math.max(12, rect.right - width), window.innerWidth - width - 12);
    const maxMenuHeight = Math.min(420, window.innerHeight - 32);
    const below = rect.bottom + 8;
    const top = below + maxMenuHeight <= window.innerHeight - 12
      ? below
      : Math.max(12, rect.top - maxMenuHeight - 8);
    setMenuPosition({
      top,
      left,
      width,
    });
  };

  useLayoutEffect(() => {
    if (open) updatePosition();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handlePointerDown = (event: PointerEvent) => {
      const target = event.target as HTMLElement | null;
      if (buttonRef.current?.contains(target)) return;
      if (target?.closest('[data-add-investigation-menu="true"]')) return;
      setOpen(false);
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    window.addEventListener('pointerdown', handlePointerDown);
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
      window.removeEventListener('pointerdown', handlePointerDown);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  const menu = open ? (
    <div
      data-add-investigation-menu="true"
      className="fixed z-[9999] max-h-[min(420px,calc(100vh-32px))] overflow-y-auto rounded-lg border border-gray-700 bg-gray-950 p-3 shadow-2xl shadow-black/50"
      style={{ top: menuPosition.top, left: menuPosition.left, width: menuPosition.width }}
    >
      <div className="mb-2 flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-semibold text-white">Add analytic result</div>
          <p className="mt-1 text-[10px] leading-4 text-gray-500">{payload.label}</p>
        </div>
        <button type="button" onClick={() => setOpen(false)} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-400 hover:border-gray-500 hover:text-white">
          Close
        </button>
      </div>
      {isLoading ? (
        <p className="text-xs text-gray-500">Loading investigations...</p>
      ) : investigations.length ? (
        <>
          <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wide text-gray-500">Investigation</label>
          <select
            value={selected?.id ?? ''}
            onChange={event => setSelectedId(event.target.value)}
            className="field mb-2 w-full text-xs"
          >
            {investigations.map(item => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => addMutation.mutate()}
            disabled={addMutation.isPending}
            className="primary-action w-full text-xs disabled:opacity-50"
          >
            {addMutation.isPending ? 'Adding...' : 'Add to selected investigation'}
          </button>
        </>
      ) : (
        <div className="space-y-3">
          <p className="text-xs leading-5 text-amber-300">
            No investigation exists yet. Create a case workspace first, then add this analytic result.
          </p>
          <a href="/report" className="primary-action block text-center text-xs">
            Open Investigation page
          </a>
        </div>
      )}
      {message && <p className="mt-2 text-[10px] text-gray-400">{message}</p>}
    </div>
  ) : null;

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      {canAdd ? <button
        ref={buttonRef}
        type="button"
        disabled={disabled}
        onClick={() => {
          setOpen(value => !value);
          setMessage('');
        }}
        className={className}
      >
        + Add to investigation
      </button> : !canManage
        ? <PermissionNotice permission="manage_intel" action="add results to an investigation" compact />
        : <PermissionNotice permission="run_analysis" action="open and select an investigation" compact />}
      {canRunAnalysis && (
        <Link
          to="/report"
          className="rounded bg-gray-700 px-3 py-1.5 text-xs text-white hover:bg-gray-600"
        >
          Open Investigation
        </Link>
      )}
      {typeof document !== 'undefined' && menu ? createPortal(menu, document.body) : null}
    </span>
  );
}

function mergeInvestigation(row: Investigation, payload: InvestigationPayload): InvestigationBody {
  const now = new Date().toISOString();
  return {
    name: row.name,
    description: row.description || payload.description || '',
    status: row.status || 'active',
    domain: row.domain || payload.domain,
    actor_ids: mergeStrings(row.actor_ids, payload.actorIds),
    technique_ids: mergeStrings(row.technique_ids, payload.techniqueIds?.map(item => item.toUpperCase())),
    report_ids: mergeStrings(row.report_ids, payload.reportIds),
    evidence_nodes: mergeObjects(row.evidence_nodes, payload.evidenceNodes),
    evidence_edges: mergeObjects(row.evidence_edges, payload.evidenceEdges),
    timeline: [
      ...(row.timeline ?? []),
      {
        at: now,
        event: payload.timelineEvent || `Added analytic result: ${payload.label}`,
        source: payload.label,
        technique_count: payload.techniqueIds?.length ?? 0,
        actor_count: payload.actorIds?.length ?? 0,
        report_count: payload.reportIds?.length ?? 0,
      },
    ].slice(-250),
  };
}

function mergeStrings(current: string[] = [], incoming: string[] = []) {
  return Array.from(new Set([...current, ...incoming].filter(Boolean))).sort();
}

function mergeObjects(current: Array<Record<string, unknown>> = [], incoming: Array<Record<string, unknown>> = []) {
  const merged = new Map<string, Record<string, unknown>>();
  [...current, ...incoming].forEach(item => {
    const key = String(item.id ?? item.value ?? item.label ?? JSON.stringify(item));
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, normalizeEvidenceObject(item));
      return;
    }
    merged.set(key, mergeEvidenceObject(existing, item));
  });
  return Array.from(merged.values()).slice(-750);
}

function normalizeEvidenceObject(item: Record<string, unknown>) {
  return {
    ...item,
    source_refs: mergeStringArrays([], collectSourceRefs(item)),
  };
}

function mergeEvidenceObject(existing: Record<string, unknown>, incoming: Record<string, unknown>) {
  return {
    ...existing,
    ...Object.fromEntries(Object.entries(incoming).filter(([, value]) => value !== undefined && value !== null && value !== '')),
    source_refs: mergeStringArrays(collectSourceRefs(existing), collectSourceRefs(incoming)),
  };
}

function collectSourceRefs(item: Record<string, unknown>) {
  const refs = [
    ...toStringArray(item.source_refs),
    ...toStringArray(item.references),
    ...toStringArray(item.refs),
    item.source_ref,
    item.source,
    item.provider,
  ];
  return refs.map(value => String(value ?? '').trim()).filter(Boolean);
}

function toStringArray(value: unknown) {
  return Array.isArray(value) ? value.map(item => String(item)) : [];
}

function mergeStringArrays(current: string[] = [], incoming: string[] = []) {
  return Array.from(new Set([...current, ...incoming].filter(Boolean))).slice(-50);
}
