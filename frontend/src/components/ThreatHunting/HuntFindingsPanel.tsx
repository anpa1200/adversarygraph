import { useEffect, useMemo, useState } from 'react';

import type {
  ThreatHuntFinding,
  ThreatHuntFindingInput,
  ThreatHuntFindingVerdict,
  ThreatHuntQueryVersion,
  ThreatHuntTlp,
} from '@/api/client';
import { cn } from '@/utils/cn';

const VERDICTS: Array<{ value: ThreatHuntFindingVerdict; label: string }> = [
  { value: 'inconclusive', label: 'Inconclusive' },
  { value: 'supports', label: 'Supports hypothesis' },
  { value: 'refutes', label: 'Refutes hypothesis' },
  { value: 'benign', label: 'Benign explanation' },
];

const TLP_OPTIONS: ThreatHuntTlp[] = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'];

export function HuntFindingsPanel({
  findings,
  parentTlp,
  queryVersions,
  onCreate,
  onUpdate,
  onArchive,
  pending,
  error,
  readOnly,
  assistantDraft,
  onAssistantDraftConsumed,
  onDirtyChange,
  onOpenAssistant,
}: {
  findings: ThreatHuntFinding[];
  parentTlp: ThreatHuntTlp;
  queryVersions: ThreatHuntQueryVersion[];
  onCreate: (finding: ThreatHuntFindingInput) => Promise<void>;
  onUpdate: (findingId: string, patch: Partial<ThreatHuntFindingInput>) => Promise<void>;
  onArchive: (findingId: string) => Promise<void>;
  pending: boolean;
  error: string;
  readOnly: boolean;
  assistantDraft: { key: number; draft: Partial<ThreatHuntFindingInput> } | null;
  onAssistantDraftConsumed: () => void;
  onDirtyChange: (dirty: boolean) => void;
  onOpenAssistant: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<ThreatHuntFindingInput>(() => emptyFinding(parentTlp));
  const [baselineFingerprint, setBaselineFingerprint] = useState(() => findingFingerprint(emptyFinding(parentTlp)));
  const [editingId, setEditingId] = useState<string | null>(null);
  const [archiveConfirmId, setArchiveConfirmId] = useState<string | null>(null);
  const [formError, setFormError] = useState('');
  const editingFinding = findings.find(finding => finding.id === editingId);
  const minimumTlp = moreRestrictiveTlp(parentTlp, editingFinding?.tlp);
  const allowedTlps = useMemo(() => tlpsAtLeast(minimumTlp), [minimumTlp]);
  const findingDirty = open && findingFingerprint(draft) !== baselineFingerprint;

  useEffect(() => {
    onDirtyChange(findingDirty);
  }, [findingDirty, onDirtyChange]);

  useEffect(() => () => onDirtyChange(false), [onDirtyChange]);

  useEffect(() => {
    if (!allowedTlps.includes(draft.tlp)) setDraft(current => ({ ...current, tlp: parentTlp }));
  }, [allowedTlps, draft.tlp, parentTlp]);

  useEffect(() => {
    if (!assistantDraft) return;
    const empty = emptyFinding(parentTlp);
    setEditingId(null);
    setDraft(safeAssistantFindingDraft(assistantDraft.draft, parentTlp));
    setBaselineFingerprint(findingFingerprint(empty));
    setFormError('');
    setArchiveConfirmId(null);
    setOpen(true);
    onAssistantDraftConsumed();
  }, [assistantDraft, onAssistantDraftConsumed, parentTlp]);

  const closeForm = (force = false) => {
    if (!force && findingDirty && !window.confirm('Discard unsaved finding changes?')) return;
    const empty = emptyFinding(parentTlp);
    setOpen(false);
    setEditingId(null);
    setDraft(empty);
    setBaselineFingerprint(findingFingerprint(empty));
    setFormError('');
  };

  const startCreate = () => {
    const empty = emptyFinding(parentTlp);
    setEditingId(null);
    setDraft(empty);
    setBaselineFingerprint(findingFingerprint(empty));
    setFormError('');
    setOpen(true);
  };

  const startEdit = (finding: ThreatHuntFinding) => {
    if (findingDirty && !window.confirm('Discard unsaved finding changes?')) return;
    const next = toFindingInput(finding);
    setEditingId(finding.id);
    setDraft(next);
    setBaselineFingerprint(findingFingerprint(next));
    setFormError('');
    setArchiveConfirmId(null);
    setOpen(true);
  };

  const submit = async () => {
    const validation = validateFinding(draft);
    if (validation) {
      setFormError(validation);
      return;
    }
    const body = {
      ...draft,
      title: draft.title.trim(),
      evidence_type: draft.evidence_type.trim(),
      observables: cleanList(draft.observables),
      technique_ids: cleanList(draft.technique_ids).map(value => value.toUpperCase()),
    };
    setFormError('');
    try {
      if (editingId) await onUpdate(editingId, body);
      else await onCreate(body);
      closeForm(true);
    } catch (caught) {
      setFormError(errorMessage(caught));
    }
  };

  const archive = async (findingId: string) => {
    setFormError('');
    try {
      await onArchive(findingId);
      if (editingId === findingId) closeForm(true);
      setArchiveConfirmId(null);
    } catch (caught) {
      setFormError(errorMessage(caught));
    }
  };

  return (
    <div className="space-y-4">
      <section className="rounded border border-gray-800 bg-gray-950/50 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-white">Evidence and findings</h2>
            <p className="mt-1 text-xs leading-5 text-gray-500">Record only evidence reviewed during this hunt. A finding can support, refute, or leave the hypothesis unresolved.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="secondary-action min-h-9 border-cyan-800 px-3 text-cyan-100 disabled:opacity-40"
              disabled={open}
              title={open ? 'Close the current finding form before opening the AI assistant.' : undefined}
              onClick={onOpenAssistant}
            >
              AI assist findings
            </button>
            {!readOnly && (
              <button type="button" className="primary min-h-9" onClick={open ? () => closeForm() : startCreate}>
                {open ? 'Close form' : 'Add finding'}
              </button>
            )}
          </div>
        </div>

        {open && (
          <div className="mt-4 grid gap-4 border-t border-gray-800 pt-4 lg:grid-cols-2">
            <div className="lg:col-span-2">
              <h3 className="text-sm font-semibold text-white">{editingId ? 'Correct finding record' : 'Record a finding'}</h3>
              <p className="mt-1 text-[11px] text-gray-600">Changes remain in this form after a failed save. Closing or leaving with unsaved edits requires confirmation.</p>
            </div>
            <Field label="Finding title" required>
              <input className="field" value={draft.title} onChange={event => setDraft({ ...draft, title: event.target.value })} placeholder="What was observed?" />
            </Field>
            <div className="grid grid-cols-3 gap-3">
              <Field label="Status">
                <select aria-label="Finding status" className="field" value={draft.status} onChange={event => setDraft({ ...draft, status: event.target.value as ThreatHuntFindingInput['status'] })}>
                  {['new', 'reviewed', 'escalated', 'closed'].map(value => <option key={value}>{value}</option>)}
                </select>
              </Field>
              <Field label="Severity">
                <select aria-label="Finding severity" className="field" value={draft.severity} onChange={event => setDraft({ ...draft, severity: event.target.value as ThreatHuntFindingInput['severity'] })}>
                  {['informational', 'low', 'medium', 'high', 'critical'].map(value => <option key={value}>{value}</option>)}
                </select>
              </Field>
              <Field label="Confidence">
                <input aria-label="Finding confidence" className="field" type="number" min={0} max={100} value={draft.confidence} onChange={event => setDraft({ ...draft, confidence: clamp(Number(event.target.value), 0, 100) })} />
              </Field>
            </div>
            <Field label="Summary">
              <textarea className="field min-h-24" value={draft.summary} onChange={event => setDraft({ ...draft, summary: event.target.value })} placeholder="Evidence, context, and why it matters" />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Verdict">
                <select aria-label="Finding verdict" className="field" value={draft.verdict} onChange={event => setDraft({ ...draft, verdict: event.target.value as ThreatHuntFindingVerdict })}>
                  {VERDICTS.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}
                </select>
              </Field>
              <Field label="TLP">
                <select aria-label="Finding TLP" className="field" value={draft.tlp} onChange={event => setDraft({ ...draft, tlp: event.target.value as ThreatHuntTlp })}>
                  {allowedTlps.map(value => <option key={value}>{value}</option>)}
                </select>
              </Field>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Evidence type">
                <input aria-label="Finding evidence type" className="field" value={draft.evidence_type} onChange={event => setDraft({ ...draft, evidence_type: event.target.value })} placeholder="SIEM event, EDR alert, analyst note" />
              </Field>
              <Field label="Event time">
                <input aria-label="Finding event time" className="field" type="datetime-local" value={toLocalDate(draft.event_time)} onChange={event => setDraft({ ...draft, event_time: toIsoDate(event.target.value) })} />
              </Field>
            </div>
            <Field label="Evidence reference">
              <input aria-label="Finding evidence reference" className="field font-mono text-xs" value={draft.evidence_ref} onChange={event => setDraft({ ...draft, evidence_ref: event.target.value })} placeholder="Case-safe event ID, report URL, or evidence record" />
            </Field>
            <Field label="Observables">
              <input aria-label="Finding observables" className="field" value={draft.observables.join(', ')} onChange={event => setDraft({ ...draft, observables: splitList(event.target.value) })} placeholder="host-01, 10.0.0.5, example.com" />
            </Field>
            <Field label="ATT&CK techniques">
              <input className="field font-mono uppercase" value={draft.technique_ids.join(', ')} onChange={event => setDraft({ ...draft, technique_ids: splitList(event.target.value) })} placeholder="T1059.001, T1027" />
            </Field>
            <Field label="Analyst notes">
              <textarea className="field min-h-20" value={draft.notes} onChange={event => setDraft({ ...draft, notes: event.target.value })} placeholder="Validation, alternative explanations, and follow-up" />
            </Field>
            <div className="flex items-end justify-end">
              <button type="button" className="primary min-h-10 px-5" disabled={pending || draft.title.trim().length < 3} onClick={() => void submit()}>
                {pending ? 'Saving…' : editingId ? 'Save corrections' : 'Save finding'}
              </button>
            </div>
          </div>
        )}
        {(formError || error) && <p role="alert" className="mt-3 text-xs text-red-300">{formError || error}</p>}
      </section>

      <div className="grid gap-3 xl:grid-cols-2">
        {findings.map(finding => (
          <article key={finding.id} className="rounded border border-gray-800 bg-gray-950/50 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex flex-wrap gap-2">
                  <Severity value={finding.severity} />
                  <span className="rounded border border-gray-700 px-2 py-0.5 text-[10px] text-gray-400">{finding.tlp}</span>
                  <span className="rounded border border-gray-700 px-2 py-0.5 text-[10px] text-gray-400">{verdictLabel(finding.verdict)}</span>
                  {finding.query_version_id && (
                    <span className="rounded border border-cyan-900 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
                      query v{queryVersions.find(version => version.id === finding.query_version_id)?.version ?? '?'}
                    </span>
                  )}
                </div>
                <h3 className="mt-3 text-sm font-semibold text-white">{finding.title}</h3>
              </div>
              <div className="flex flex-wrap items-center justify-end gap-2">
                <select
                  aria-label={`Status for ${finding.title}`}
                  className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-300"
                  value={finding.status}
                  disabled={readOnly || pending}
                  onChange={event => {
                    void onUpdate(finding.id, { status: event.target.value as ThreatHuntFindingInput['status'] }).catch(() => undefined);
                  }}
                >
                  {['new', 'reviewed', 'escalated', 'closed'].map(value => <option key={value}>{value}</option>)}
                </select>
                {!readOnly && (
                  <button type="button" className="secondary-action px-2 py-1 text-xs" disabled={pending} onClick={() => startEdit(finding)}>
                    Edit finding
                  </button>
                )}
                {!readOnly && archiveConfirmId !== finding.id && (
                  <button type="button" className="px-2 py-1 text-xs text-amber-300 hover:text-amber-100" disabled={pending} onClick={() => setArchiveConfirmId(finding.id)}>
                    Archive finding
                  </button>
                )}
                {!readOnly && archiveConfirmId === finding.id && (
                  <span className="flex items-center gap-1" role="group" aria-label={`Confirm archive for ${finding.title}`}>
                    <button type="button" className="rounded bg-amber-700 px-2 py-1 text-xs text-white" disabled={pending} onClick={() => void archive(finding.id)}>Confirm archive</button>
                    <button type="button" className="px-2 py-1 text-xs text-gray-400" disabled={pending} onClick={() => setArchiveConfirmId(null)}>Keep</button>
                  </span>
                )}
              </div>
            </div>
            <p className="mt-3 whitespace-pre-wrap text-xs leading-5 text-gray-400">{finding.summary || 'No summary recorded.'}</p>
            {finding.evidence_ref && <p className="mt-3 break-all rounded bg-gray-900 p-2 font-mono text-[10px] text-cyan-200">{finding.evidence_ref}</p>}
            {finding.notes && <p className="mt-3 whitespace-pre-wrap text-[11px] leading-5 text-gray-500">{finding.notes}</p>}
            <div className="mt-3 flex flex-wrap gap-1">
              {finding.technique_ids.map(id => <span key={id} className="rounded bg-cyan-950 px-2 py-1 font-mono text-[10px] text-cyan-200">{id}</span>)}
              {finding.observables.map(value => <span key={value} className="rounded bg-gray-800 px-2 py-1 font-mono text-[10px] text-gray-400">{value}</span>)}
            </div>
            <div className="mt-3 border-t border-gray-800 pt-3 text-[10px] text-gray-600">
              {finding.analyst || 'Server-recorded analyst'} · {formatDate(finding.created_at)} · confidence {finding.confidence}%
            </div>
          </article>
        ))}
        {!findings.length && (
          <div className="rounded border border-dashed border-gray-800 p-10 text-center text-sm text-gray-600 xl:col-span-2">
            No findings recorded. “No matches” is a hunt result, not proof that the environment is clean.
          </div>
        )}
      </div>
    </div>
  );
}

function emptyFinding(tlp: ThreatHuntTlp): ThreatHuntFindingInput {
  return {
    title: '',
    summary: '',
    severity: 'informational',
    confidence: 50,
    status: 'new',
    verdict: 'inconclusive',
    tlp,
    evidence_type: 'event',
    evidence_ref: '',
    event_time: null,
    observables: [],
    technique_ids: [],
    notes: '',
  };
}

function findingFingerprint(finding: ThreatHuntFindingInput) {
  return JSON.stringify(finding);
}

function safeAssistantFindingDraft(
  suggestion: Partial<ThreatHuntFindingInput>,
  parentTlp: ThreatHuntTlp,
): ThreatHuntFindingInput {
  const draft = emptyFinding(parentTlp);
  const severities: ThreatHuntFindingInput['severity'][] = ['informational', 'low', 'medium', 'high', 'critical'];
  return {
    ...draft,
    title: typeof suggestion.title === 'string' ? suggestion.title : '',
    summary: typeof suggestion.summary === 'string' ? suggestion.summary : '',
    severity: suggestion.severity && severities.includes(suggestion.severity) ? suggestion.severity : draft.severity,
    confidence: typeof suggestion.confidence === 'number' ? clamp(suggestion.confidence, 0, 100) : draft.confidence,
    status: 'new',
    verdict: 'inconclusive',
    tlp: parentTlp,
    evidence_type: 'analysis',
    evidence_ref: '',
    event_time: null,
    observables: [],
    technique_ids: Array.isArray(suggestion.technique_ids)
      ? cleanList(suggestion.technique_ids).map(value => value.toUpperCase()).filter(value => /^T\d{4}(?:\.\d{3})?$/.test(value))
      : [],
    query_version_id: null,
    notes: typeof suggestion.notes === 'string' ? suggestion.notes : '',
  };
}

function toFindingInput(finding: ThreatHuntFinding): ThreatHuntFindingInput {
  return {
    title: finding.title,
    summary: finding.summary,
    severity: finding.severity,
    confidence: finding.confidence,
    status: finding.status,
    verdict: finding.verdict,
    tlp: finding.tlp,
    evidence_type: finding.evidence_type,
    evidence_ref: finding.evidence_ref,
    event_time: finding.event_time,
    observables: [...finding.observables],
    technique_ids: [...finding.technique_ids],
    query_version_id: finding.query_version_id,
    notes: finding.notes,
  };
}

function validateFinding(finding: ThreatHuntFindingInput) {
  if (finding.title.trim().length < 3) return 'Add a finding title with at least three characters.';
  if (finding.evidence_type.trim().length < 2) return 'Evidence type must contain at least two characters.';
  const invalidTechniques = finding.technique_ids.filter(value => !/^T\d{4}(?:\.\d{3})?$/.test(value.trim().toUpperCase()));
  if (invalidTechniques.length) return `Correct invalid ATT&CK technique IDs: ${invalidTechniques.join(', ')}.`;
  return '';
}

function Field({ label, children, required = false }: { label: string; children: React.ReactNode; required?: boolean }) {
  return <label className="text-xs text-gray-500">{label}{required && <span className="ml-1 text-red-400">*</span>}<div className="mt-1">{children}</div></label>;
}

function Severity({ value }: { value: ThreatHuntFinding['severity'] }) {
  const tone = value === 'critical' ? 'border-red-500 text-red-200' : value === 'high' ? 'border-orange-600 text-orange-200' : value === 'medium' ? 'border-amber-700 text-amber-200' : 'border-gray-700 text-gray-400';
  return <span className={cn('rounded border px-2 py-0.5 text-[10px] font-semibold capitalize', tone)}>{value}</span>;
}

function verdictLabel(value: ThreatHuntFindingVerdict) {
  return VERDICTS.find(item => item.value === value)?.label ?? value;
}

function tlpsAtLeast(parent: ThreatHuntTlp) {
  const index = TLP_OPTIONS.indexOf(parent);
  return index < 0 ? TLP_OPTIONS : TLP_OPTIONS.slice(index);
}

function moreRestrictiveTlp(first: ThreatHuntTlp, second?: ThreatHuntTlp) {
  if (!second) return first;
  return TLP_OPTIONS.indexOf(second) > TLP_OPTIONS.indexOf(first) ? second : first;
}

function splitList(value: string) {
  return value.split(/[\n,]/).map(item => item.trim()).filter(Boolean);
}

function cleanList(values: string[]) {
  return Array.from(new Set(values.map(value => value.trim()).filter(Boolean)));
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, Number.isFinite(value) ? value : min));
}

function toLocalDate(value: string | null) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function toIsoDate(value: string) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString();
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : error ? String(error) : 'Unable to save the finding.';
}
