import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';

import {
  threatHuntingApi,
  type ThreatHunt,
  type ThreatHuntDetail,
  type ThreatHuntDisposition,
  type ThreatHuntFindingInput,
  type ThreatHuntInput,
  type ThreatHuntPriority,
  type ThreatHuntQueryLanguage,
  type ThreatHuntQueryVersion,
  type ThreatHuntStatus,
  type ThreatHuntTemplate,
  type ThreatHuntTlp,
  type HuntQueryLibraryItem,
  type IOCQueryBuildResult,
} from '@/api/client';
import { CodeEditor } from '@/components/ui/code-editor';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { HuntAIAssistant, type HuntAIAssistantMode } from './HuntAIAssistant';
import { HuntFindingsPanel } from './HuntFindingsPanel';
import { HuntPriorityPill, HuntStatusPill } from './HuntStatusPill';
import { THREAT_HUNT_QUERY_LANGUAGES, THREAT_HUNT_QUERY_LANGUAGE_OPTIONS } from './queryLanguages';
import { useHasPermission } from '@/hooks/useCurrentUser';

const PRIORITIES: ThreatHuntPriority[] = ['P0 Emergency', 'P1 High', 'P2 Medium', 'P3 Monitor', 'P4 Low/Archive'];
const TLP_OPTIONS: ThreatHuntTlp[] = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'];
const DISPOSITIONS: Array<{ value: ThreatHuntDisposition; label: string; help: string }> = [
  { value: 'undetermined', label: 'Undetermined', help: 'The hunt has not reached a reviewed outcome.' },
  { value: 'no_matches', label: 'No matches observed', help: 'No matching evidence was found in the searched scope; this does not mean the environment is clean.' },
  { value: 'benign', label: 'Benign activity', help: 'Reviewed evidence has a supported benign explanation.' },
  { value: 'benign_policy_relevant', label: 'Benign but policy-relevant', help: 'Not malicious, but the behavior requires a policy or control follow-up.' },
  { value: 'suspicious', label: 'Suspicious', help: 'Evidence warrants additional investigation.' },
  { value: 'confirmed_malicious', label: 'Confirmed malicious', help: 'Evidence supports escalation through the incident-response process.' },
  { value: 'inconclusive', label: 'Inconclusive', help: 'Available evidence cannot support or refute the hypothesis.' },
  { value: 'telemetry_gap', label: 'Telemetry gap', help: 'Required data was missing or insufficient.' },
  { value: 'query_failure', label: 'Query failure', help: 'The query could not be completed or validated in the approved telemetry tool.' },
];

const STATUS_ACTIONS: Partial<Record<ThreatHuntStatus, Array<{ status: ThreatHuntStatus; label: string }>>> = {
  queued: [
    { status: 'planned', label: 'Accept into plan' },
    { status: 'running', label: 'Start analyst hunt' },
  ],
  draft: [{ status: 'planned', label: 'Mark planned' }],
  planned: [{ status: 'running', label: 'Start analyst hunt' }],
  running: [{ status: 'review', label: 'Send to review' }],
  review: [
    { status: 'running', label: 'Return to running' },
    { status: 'completed', label: 'Complete hunt' },
  ],
};

export function HuntWorkspace({
  hunt,
  templates,
  initialTemplateId,
  initialTechniques,
  initialSourceType,
  initialSourceRef,
  initialSourceSessionId,
  initialAssistantMode,
  initialLibraryItem,
  defaultOwner,
  loading,
  loadError,
  onBack,
  onCreated,
}: {
  hunt: ThreatHuntDetail | null;
  templates: ThreatHuntTemplate[];
  initialTemplateId: string;
  initialTechniques: string[];
  initialSourceType: string;
  initialSourceRef: string;
  initialSourceSessionId: string;
  initialAssistantMode: HuntAIAssistantMode | '';
  initialLibraryItem: HuntQueryLibraryItem | IOCQueryBuildResult | null;
  defaultOwner: string;
  loading: boolean;
  loadError: string;
  onBack: () => void;
  onCreated: (id: string) => void;
}) {
  const qc = useQueryClient();
  const canExport = useHasPermission('export_data');
  const canRunSimulation = useHasPermission('run_attack_simulation');
  const initialized = useRef('');
  const [draft, setDraft] = useState<ThreatHuntInput>(() => emptyHunt(defaultOwner));
  const [savedFingerprint, setSavedFingerprint] = useState(() => draftFingerprint(emptyHunt(defaultOwner)));
  const [findingFormDirty, setFindingFormDirty] = useState(false);
  const [tab, setTab] = useState('plan');
  const [validationError, setValidationError] = useState('');
  const [copyState, setCopyState] = useState('');
  const [confirmArchive, setConfirmArchive] = useState(false);
  const [assistantOpen, setAssistantOpen] = useState(false);
  const [assistantMode, setAssistantMode] = useState<HuntAIAssistantMode>(initialAssistantMode || 'plan');
  const [assistantFindingDraft, setAssistantFindingDraft] = useState<{ key: number; draft: Partial<ThreatHuntFindingInput> } | null>(null);
  const initialAssistantOpened = useRef('');
  const initialTechniquesKey = initialTechniques.join('\u0000');

  useEffect(() => {
    const libraryKey = initialLibraryItem ? String(initialLibraryItem.query_text.length) : '';
    const key = hunt ? `hunt:${hunt.id}` : `new:${initialTemplateId}:${initialTechniquesKey}:${initialSourceType}:${initialSourceRef}:${initialSourceSessionId}:${libraryKey}`;
    if (initialized.current === key) return;
    if (!hunt && initialTemplateId && !templates.length) return;
    initialized.current = key;

    if (hunt) {
      const next = toInput(hunt);
      setDraft(next);
      setSavedFingerprint(draftFingerprint(next));
      setFindingFormDirty(false);
      return;
    }

    const template = templates.find(item => item.id === initialTemplateId);
    const next = template ? applyTemplate(emptyHunt(defaultOwner), template) : emptyHunt(defaultOwner);
    if (initialLibraryItem) {
      next.title = initialLibraryItem.title.replace(/\s+—\s+(Sigma|YARA-L)$/i, '');
      next.hypothesis = `If activity matching “${next.title}” is present in the scoped environment, then selected telemetry should contain events matching the reviewed query.`;
      next.description = initialLibraryItem.description;
      next.query_language = ('query_language' in initialLibraryItem ? initialLibraryItem.query_language : initialLibraryItem.language) as ThreatHuntQueryLanguage;
      next.query_text = initialLibraryItem.query_text;
      next.technique_ids = [...initialLibraryItem.technique_ids];
      next.tags = unique([...next.tags, ...initialLibraryItem.tags, 'query-library']);
      if ('data_sources' in initialLibraryItem) next.telemetry_sources = [...initialLibraryItem.data_sources];
      next.assumptions = 'Imported from the AdversaryGraph query library. Validate destination schema, field mappings, data availability, time range, exclusions, syntax, and IOC freshness before execution.';
    }
    const requestedTechniques = initialTechniquesKey ? initialTechniquesKey.split('\u0000') : [];
    next.technique_ids = unique([...next.technique_ids, ...requestedTechniques.map(value => value.toUpperCase())]);
    const triggerType = initialSourceType || (requestedTechniques.length ? 'navigator' : '');
    next.tags = unique([
      ...next.tags,
      ...(triggerType ? [`context:${triggerType.trim().slice(0, 492)}`] : []),
      ...(initialSourceRef ? [`context-ref:${initialSourceRef.trim().slice(0, 488)}`] : []),
    ]);
    setDraft(next);
    setSavedFingerprint(draftFingerprint(emptyHunt(defaultOwner)));
    setFindingFormDirty(false);
  }, [defaultOwner, hunt, initialLibraryItem, initialSourceRef, initialSourceSessionId, initialSourceType, initialTechniquesKey, initialTemplateId, templates]);

  useEffect(() => {
    if (!initialAssistantMode) return;
    const key = `${initialAssistantMode}:${initialSourceSessionId}:${initialSourceRef}`;
    if (initialAssistantOpened.current === key) return;
    initialAssistantOpened.current = key;
    setAssistantMode(initialAssistantMode);
    setAssistantOpen(true);
  }, [initialAssistantMode, initialSourceRef, initialSourceSessionId]);

  const invalidate = async (huntId?: string) => {
    await Promise.all([
      qc.invalidateQueries({ queryKey: ['threat-hunting-stats'] }),
      qc.invalidateQueries({ queryKey: ['threat-hunting-hunts'] }),
      ...(huntId ? [qc.invalidateQueries({ queryKey: ['threat-hunting-hunt', huntId] })] : []),
    ]);
  };

  const createHunt = useMutation({
    mutationFn: (body: ThreatHuntInput) => threatHuntingApi.create(body),
    onSuccess: async created => {
      const next = toInput(created);
      setDraft(next);
      setSavedFingerprint(draftFingerprint(next));
      await invalidate(created.id);
      onCreated(created.id);
    },
  });
  const updateHunt = useMutation({
    mutationFn: (body: ThreatHuntInput) => threatHuntingApi.update(hunt!.id, body),
    onSuccess: async updated => {
      const next = toInput(updated);
      setDraft(next);
      setSavedFingerprint(draftFingerprint(next));
      await invalidate(updated.id);
    },
  });
  const archiveHunt = useMutation({
    mutationFn: () => threatHuntingApi.archive(hunt!.id),
    onSuccess: async updated => {
      const next = toInput(updated);
      setDraft(next);
      setSavedFingerprint(draftFingerprint(next));
      setConfirmArchive(false);
      await invalidate(updated.id);
    },
  });
  const createFinding = useMutation({
    mutationFn: (body: ThreatHuntFindingInput) => threatHuntingApi.createFinding(hunt!.id, body),
    onSuccess: async () => invalidate(hunt!.id),
  });
  const updateFinding = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Partial<ThreatHuntFindingInput> }) => threatHuntingApi.updateFinding(hunt!.id, id, patch),
    onSuccess: async () => invalidate(hunt!.id),
  });
  const archiveFinding = useMutation({
    mutationFn: (findingId: string) => threatHuntingApi.archiveFinding(hunt!.id, findingId),
    onSuccess: async () => invalidate(hunt!.id),
  });

  const isNew = !hunt;
  const saving = createHunt.isPending || updateHunt.isPending;
  const saveError = errorMessage(createHunt.error || updateHunt.error || archiveHunt.error);
  const terminal = ['completed', 'cancelled', 'archived'].includes(draft.status);
  const statusActions = hunt ? STATUS_ACTIONS[draft.status] ?? [] : [];
  const canCancel = Boolean(hunt && ['queued', 'draft', 'planned', 'running', 'review'].includes(draft.status));
  const huntTlpOptions = useMemo(() => hunt ? tlpsAtLeast(hunt.tlp) : TLP_OPTIONS, [hunt]);
  const disposition = DISPOSITIONS.find(item => item.value === draft.disposition) ?? DISPOSITIONS[0];
  const readiness = useMemo(() => readinessChecks(draft), [draft]);
  const huntDraftDirty = draftFingerprint(draft) !== savedFingerprint;
  const unsavedChanges = huntDraftDirty || findingFormDirty;
  const confirmDiscard = useUnsavedChangesGuard(unsavedChanges);

  const save = (next = draft) => {
    const error = validate(next, next.status);
    if (error) {
      setValidationError(error);
      return;
    }
    setValidationError('');
    isNew ? createHunt.mutate(normalize(next)) : updateHunt.mutate(normalize(next));
  };

  const transition = (status: ThreatHuntStatus) => {
    const next = { ...draft, status };
    const error = validate(next, status) || (status === 'completed' ? validateCompletion(next, hunt?.findings ?? []) : '');
    if (error) {
      setValidationError(error);
      setTab(status === 'completed' && hunt?.findings.some(finding => finding.status === 'new') ? 'findings' : status === 'completed' ? 'outcome' : 'plan');
      return;
    }
    save(next);
  };

  const copyQuery = async () => {
    try {
      await copyText(draft.query_text);
      setCopyState('Query copied');
    } catch {
      setCopyState('Copy failed');
    }
    window.setTimeout(() => setCopyState(''), 2000);
  };

  const openAssistant = (mode: HuntAIAssistantMode) => {
    setAssistantMode(mode);
    setAssistantOpen(true);
  };

  const applyAssistantPatch = (patch: Partial<ThreatHuntInput>, stage: HuntAIAssistantMode) => {
    setDraft(current => applySafeAssistantPatch(current, patch, stage));
  };

  if (loading) return <WorkspaceState text="Loading threat hunt…" onBack={onBack} />;
  if (loadError) return <WorkspaceState text={loadError} onBack={onBack} error />;

  return (
    <main className="flex-1 px-6 py-6">
      <div className="mx-auto max-w-[1500px] space-y-4">
        <section className="rounded-lg border border-gray-800 bg-gray-900/60">
          <div className="flex flex-wrap items-start justify-between gap-4 p-4">
            <div className="min-w-0">
              <button
                type="button"
                onClick={() => {
                  if (confirmDiscard()) onBack();
                }}
                className="text-xs text-gray-500 hover:text-white"
              >
                ← Hunt queue
              </button>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <HuntStatusPill status={draft.status} />
                <HuntPriorityPill priority={draft.priority} />
                <span className="rounded border border-gray-700 px-2 py-0.5 text-[10px] text-gray-400">{draft.tlp}</span>
              </div>
              <h1 className="mt-3 truncate text-xl font-semibold text-white">{draft.title || 'New threat hunt'}</h1>
              <p className="mt-2 max-w-4xl text-xs leading-5 text-gray-500">
                This workspace records the hunt plan, query, evidence, and outcome. It does not execute queries against a SIEM or endpoint platform.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {unsavedChanges && <span role="status" className="text-xs font-medium text-amber-300">Unsaved changes</span>}
              {!isNew && canExport && <a className="secondary-action inline-flex min-h-9 items-center px-3" href={threatHuntingApi.exportUrl(hunt.id)} download>Export JSON</a>}
              {statusActions.map(action => (
                <button
                  key={action.status}
                  type="button"
                  className="secondary-action min-h-9 px-3"
                  disabled={saving}
                  onClick={() => transition(action.status)}
                >
                  {action.label}
                </button>
              ))}
              {canCancel && (
                <button type="button" className="secondary-action min-h-9 px-3 text-rose-300" disabled={saving} onClick={() => transition('cancelled')}>Cancel hunt</button>
              )}
              {!terminal && <button type="button" className="primary min-h-9 px-4" disabled={saving} onClick={() => save()}>{saving ? 'Saving…' : isNew ? 'Create draft' : 'Save changes'}</button>}
            </div>
          </div>

          {(validationError || saveError) && (
            <div role="alert" className="border-t border-red-900/60 bg-red-950/25 px-4 py-3 text-xs text-red-200">{validationError || saveError}</div>
          )}

          {!isNew && draft.status !== 'archived' && (
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-gray-800 px-4 py-3">
              <p className="text-xs text-gray-600">Archive preserves the hunt and findings as read-only operational history.</p>
              {!confirmArchive ? (
                <button type="button" className="text-xs text-gray-500 hover:text-amber-300" onClick={() => setConfirmArchive(true)}>Archive hunt</button>
              ) : (
                <div className="flex items-center gap-2" role="group" aria-label="Confirm archive">
                  <span className="text-xs text-amber-200">Archive this hunt?</span>
                  <button type="button" className="rounded bg-amber-700 px-3 py-1 text-xs text-white" disabled={archiveHunt.isPending || saving} onClick={() => archiveHunt.mutate()}>Confirm</button>
                  <button type="button" className="secondary-action" onClick={() => setConfirmArchive(false)}>Keep active</button>
                </div>
              )}
            </div>
          )}
        </section>

        {isNew && templates.length > 0 && (
          <details className="rounded-lg border border-gray-800 bg-gray-900/50">
            <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-white">Start from a template</summary>
            <div className="grid gap-2 border-t border-gray-800 p-4 md:grid-cols-2 xl:grid-cols-3">
              {templates.map(template => (
                <button
                  key={template.id}
                  type="button"
                  onClick={() => {
                    if (templateWouldOverwriteDraft(draft, template) && !window.confirm('Replace the entered hunt fields with this template? Existing scalar text will be discarded.')) return;
                    setDraft(current => applyTemplate(current, template));
                  }}
                  className="rounded border border-gray-800 bg-gray-950 p-3 text-left hover:border-cyan-700"
                >
                  <b className="text-xs text-white">{template.title}</b>
                  <p className="mt-1 line-clamp-2 text-[11px] leading-4 text-gray-600">{template.hypothesis}</p>
                </button>
              ))}
            </div>
          </details>
        )}

        <Tabs value={tab} onValueChange={setTab} className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/50">
          <TabsList className="sticky top-0 z-20 bg-gray-950/95 p-3">
            <TabsTrigger value="plan">Plan and scope</TabsTrigger>
            <TabsTrigger value="query">Query and telemetry</TabsTrigger>
            <TabsTrigger value="findings" disabled={isNew}>Findings ({hunt?.findings.length ?? 0})</TabsTrigger>
            <TabsTrigger value="outcome">Outcome and handoff</TabsTrigger>
          </TabsList>

          <TabsContent value="plan" className="p-5">
            <StageAssistantHeader
              title="Plan and scope"
              description="Develop the hypothesis, scope, ATT&CK context, telemetry requirements, and limitations."
              onAssist={() => openAssistant('plan')}
              secondaryLabel="Generate hypothesis from report / research"
              onSecondary={() => openAssistant('hypothesis')}
            />
            {terminal && <ReadOnlyNotice status={draft.status} />}
            <fieldset disabled={terminal} className="mt-4 grid gap-5 disabled:opacity-70 xl:grid-cols-[minmax(0,1fr)_340px]">
              <div className="grid gap-4 lg:grid-cols-2">
                <Field label="Hunt title" required wide>
                  <input className="field" value={draft.title} onChange={event => setDraft({ ...draft, title: event.target.value })} placeholder="Suspicious encoded PowerShell execution" />
                </Field>
                <Field label="Hypothesis" required wide>
                  <textarea className="field min-h-24" value={draft.hypothesis} onChange={event => setDraft({ ...draft, hypothesis: event.target.value })} placeholder="If an adversary is performing…, then reviewed telemetry should show…" />
                </Field>
                <Field label="Description">
                  <textarea className="field min-h-24" value={draft.description} onChange={event => setDraft({ ...draft, description: event.target.value })} placeholder="Why this hunt matters and what triggered it" />
                </Field>
                <Field label="Scope">
                  <textarea className="field min-h-24" value={draft.scope} onChange={event => setDraft({ ...draft, scope: event.target.value })} placeholder="Systems, identities, environments, exclusions, and timebox" />
                </Field>
                <Field label="Owner">
                  <input className="field" value={draft.owner} onChange={event => setDraft({ ...draft, owner: event.target.value })} placeholder="Threat Hunting Team" />
                </Field>
                <Field label="Priority">
                  <select className="field" value={draft.priority} onChange={event => setDraft({ ...draft, priority: event.target.value as ThreatHuntPriority })}>
                    {PRIORITIES.map(value => <option key={value}>{value}</option>)}
                  </select>
                </Field>
                <Field label="TLP">
                  <select className="field" value={draft.tlp} onChange={event => setDraft({ ...draft, tlp: event.target.value as ThreatHuntTlp })}>
                    {huntTlpOptions.map(value => <option key={value}>{value}</option>)}
                  </select>
                </Field>
                <Field label="Creation source">
                  <input aria-label="Creation source" className="field" value={hunt?.source_type || 'manual'} readOnly />
                </Field>
                <Field label="Source reference" wide>
                  <input className="field font-mono text-xs" value={hunt?.source_ref || ''} readOnly placeholder="Assigned only by a trusted internal workflow" />
                  <p className="mt-1 text-[10px] text-gray-600">Server-assigned provenance is read-only. Analyst-provided launch context is retained as a context tag.</p>
                </Field>
                <ListField label="ATT&CK techniques" values={draft.technique_ids} onChange={technique_ids => setDraft({ ...draft, technique_ids: technique_ids.map(value => value.toUpperCase()) })} placeholder="T1059.001, T1027" mono />
                <ListField label="Tactics" values={draft.tactics} onChange={tactics => setDraft({ ...draft, tactics })} placeholder="execution, stealth, defense-impairment" />
                <ListField label="Tags" values={draft.tags} onChange={tags => setDraft({ ...draft, tags })} placeholder="endpoint, powershell, finance" wide />
              </div>
              <Readiness checks={readiness} />
            </fieldset>
          </TabsContent>

          <TabsContent value="query" className="p-5">
            <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
              <section className="overflow-hidden rounded border border-gray-800 bg-gray-950">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
                  <div>
                    <h2 className="text-sm font-semibold text-white">Hunt query</h2>
                    <p className="mt-1 text-[11px] text-gray-600">Store and review the query here, then copy it into an approved telemetry tool.</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button type="button" className="secondary-action min-h-8 px-3" onClick={() => openAssistant('query')}>Generate query</button>
                    <label className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-gray-600">
                      Query type
                      <select disabled={terminal} aria-label="Query language" className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs font-normal normal-case tracking-normal text-gray-300 disabled:opacity-60" value={draft.query_language} onChange={event => setDraft({ ...draft, query_language: event.target.value as ThreatHuntQueryLanguage })}>
                        {THREAT_HUNT_QUERY_LANGUAGE_OPTIONS.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
                      </select>
                    </label>
                    <button type="button" className="secondary-action min-h-8 px-3" disabled={!draft.query_text} onClick={copyQuery}>{copyState || 'Copy query'}</button>
                  </div>
                </div>
                <CodeEditor value={draft.query_text} language={editorLanguage(draft.query_language)} height="420px" readOnly={terminal} onChange={query_text => setDraft({ ...draft, query_text })} />
                <div className="border-t border-amber-900/50 bg-amber-950/15 px-4 py-3 text-xs leading-5 text-amber-100/80">
                  Query syntax and field names must be validated in the destination platform. AdversaryGraph does not claim this query was executed.
                </div>
              </section>

              <div className="space-y-4">
                {!isNew && hunt.query_versions.length > 0 && <QueryHistory versions={hunt.query_versions} />}
                <fieldset disabled={terminal} className="space-y-4 disabled:opacity-70">
                <Panel title="Telemetry requirements">
                  <div className="space-y-4 p-4">
                    <ListField label="Telemetry sources" values={draft.telemetry_sources} onChange={telemetry_sources => setDraft({ ...draft, telemetry_sources })} placeholder="EDR process telemetry, Sysmon, DNS logs" />
                    <ListField label="Required fields" values={draft.required_fields} onChange={required_fields => setDraft({ ...draft, required_fields })} placeholder="@timestamp, host.name, process.command_line" mono />
                  </div>
                </Panel>
                <Panel title="Time boundary">
                  <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-1">
                    <Field label="Start"><input className="field" type="datetime-local" value={toLocalDate(draft.time_range_start)} onChange={event => setDraft({ ...draft, time_range_start: toIsoDate(event.target.value) })} /></Field>
                    <Field label="End"><input className="field" type="datetime-local" value={toLocalDate(draft.time_range_end)} onChange={event => setDraft({ ...draft, time_range_end: toIsoDate(event.target.value) })} /></Field>
                  </div>
                </Panel>
                <Panel title="Interpretation criteria">
                  <div className="space-y-4 p-4">
                    <Field label="Expected evidence"><textarea className="field min-h-24" value={draft.expected_evidence} onChange={event => setDraft({ ...draft, expected_evidence: event.target.value })} /></Field>
                    <Field label="False-positive considerations"><textarea className="field min-h-24" value={draft.false_positive_notes} onChange={event => setDraft({ ...draft, false_positive_notes: event.target.value })} /></Field>
                    <Field label="Assumptions and limitations"><textarea className="field min-h-24" value={draft.assumptions} onChange={event => setDraft({ ...draft, assumptions: event.target.value })} /></Field>
                  </div>
                </Panel>
                </fieldset>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="findings" className="p-5">
            {!isNew && (
              <HuntFindingsPanel
                findings={hunt.findings}
                parentTlp={draft.tlp}
                queryVersions={hunt.query_versions}
                pending={createFinding.isPending || updateFinding.isPending || archiveFinding.isPending}
                error={errorMessage(createFinding.error || updateFinding.error || archiveFinding.error)}
                readOnly={terminal}
                assistantDraft={assistantFindingDraft}
                onAssistantDraftConsumed={() => setAssistantFindingDraft(null)}
                onDirtyChange={setFindingFormDirty}
                onOpenAssistant={() => openAssistant('findings')}
                onCreate={async body => {
                  updateFinding.reset();
                  archiveFinding.reset();
                  await createFinding.mutateAsync({ ...body, query_version_id: hunt.query_versions[0]?.id ?? null });
                }}
                onUpdate={async (id, patch) => {
                  createFinding.reset();
                  archiveFinding.reset();
                  await updateFinding.mutateAsync({ id, patch });
                }}
                onArchive={async id => {
                  createFinding.reset();
                  updateFinding.reset();
                  await archiveFinding.mutateAsync(id);
                }}
              />
            )}
          </TabsContent>

          <TabsContent value="outcome" className="p-5">
            <StageAssistantHeader
              title="Outcome and handoff"
              description="Review the result summary, limitations, evidence gaps, and defensive follow-up without changing the analyst disposition."
              onAssist={() => openAssistant('outcome')}
            />
            <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_400px]">
              <fieldset disabled={terminal} className="space-y-4 disabled:opacity-70">
                <Field label="Reviewed disposition">
                  <select className="field" value={draft.disposition} onChange={event => setDraft({ ...draft, disposition: event.target.value as ThreatHuntDisposition })}>
                    {DISPOSITIONS.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}
                  </select>
                </Field>
                <p className="rounded border border-cyan-900/50 bg-cyan-950/15 p-3 text-xs leading-5 text-cyan-100/75">{disposition.help}</p>
                <Field label="Result summary">
                  <textarea className="field min-h-56" value={draft.result_summary} onChange={event => setDraft({ ...draft, result_summary: event.target.value })} placeholder="Summarize searched scope, findings, evidence quality, gaps, and the analyst decision." />
                </Field>
              </fieldset>
              <div className="space-y-4">
                <Panel title="Completion gate">
                  <div className="p-4"><Readiness checks={completionChecks(draft, hunt?.findings ?? [])} compact /></div>
                </Panel>
                <Panel title="Defensive handoff">
                  <div className="grid gap-2 p-4">
                    <a className="secondary-action flex min-h-10 items-center justify-between px-3" href="/operations"><span>Open Operations</span><span>Investigation / detection →</span></a>
                    <a className="secondary-action flex min-h-10 items-center justify-between px-3" href="/evidence-graph"><span>Open Evidence Graph</span><span>Preserve reasoning →</span></a>
                    {canRunSimulation ? (
                      <a className="secondary-action flex min-h-10 items-center justify-between px-3" href="/attack-simulation"><span>Open Attack Simulation</span><span>Validate telemetry →</span></a>
                    ) : (
                      <p className="rounded border border-gray-800 bg-gray-950/50 px-3 py-2 text-[11px] leading-5 text-gray-500">
                        Attack Simulation handoff requires the <code className="text-gray-400">run_attack_simulation</code> permission.
                      </p>
                    )}
                    <p className="mt-2 text-[11px] leading-5 text-gray-600">Handoffs open the destination workspace. Record the resulting object ID in the result summary, finding notes, or an analyst context tag.</p>
                  </div>
                </Panel>
              </div>
            </div>
          </TabsContent>
        </Tabs>

      <HuntAIAssistant
        key={hunt?.id || `new:${initialSourceSessionId}:${initialSourceRef}`}
        open={assistantOpen}
          mode={assistantMode}
          huntId={hunt?.id}
          context={draft}
          readOnly={terminal}
          initialSourceSessionId={initialSourceSessionId}
          initialSourceType={initialSourceType}
          onOpenChange={setAssistantOpen}
          onApplyPatch={applyAssistantPatch}
          onUseFindingDraft={findingDraft => {
            setAssistantFindingDraft({ key: Date.now(), draft: findingDraft });
            setTab('findings');
          }}
        />
      </div>
    </main>
  );
}

function StageAssistantHeader({
  title,
  description,
  onAssist,
  secondaryLabel,
  onSecondary,
}: {
  title: string;
  description: string;
  onAssist: () => void;
  secondaryLabel?: string;
  onSecondary?: () => void;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3 rounded border border-cyan-900/50 bg-cyan-950/10 p-3">
      <div>
        <h2 className="text-sm font-semibold text-white">{title}</h2>
        <p className="mt-1 text-xs leading-5 text-gray-500">{description}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        {secondaryLabel && onSecondary && (
          <button type="button" className="secondary-action min-h-9 px-3" onClick={onSecondary}>{secondaryLabel}</button>
        )}
        <button type="button" className="secondary-action min-h-9 border-cyan-800 px-3 text-cyan-100" onClick={onAssist}>AI assist {title.toLowerCase()}</button>
      </div>
    </div>
  );
}

const SAFE_ASSISTANT_SCALARS: Record<HuntAIAssistantMode, Array<keyof ThreatHuntInput>> = {
  hypothesis: ['title', 'hypothesis', 'description', 'scope', 'query_text', 'expected_evidence', 'false_positive_notes', 'assumptions'],
  plan: ['title', 'hypothesis', 'description', 'scope', 'expected_evidence', 'false_positive_notes', 'assumptions'],
  query: ['query_text', 'expected_evidence', 'false_positive_notes', 'assumptions'],
  findings: [],
  outcome: ['result_summary', 'assumptions'],
};

const SAFE_ASSISTANT_ARRAYS: Record<HuntAIAssistantMode, Array<keyof ThreatHuntInput>> = {
  hypothesis: ['technique_ids', 'tactics', 'telemetry_sources', 'required_fields', 'tags'],
  plan: ['technique_ids', 'tactics', 'telemetry_sources', 'required_fields', 'tags'],
  query: ['telemetry_sources', 'required_fields'],
  findings: [],
  outcome: [],
};

function applySafeAssistantPatch(
  current: ThreatHuntInput,
  patch: Partial<ThreatHuntInput>,
  stage: HuntAIAssistantMode,
) {
  const next = { ...current };
  const currentRecord = current as unknown as Record<string, unknown>;
  const patchRecord = patch as unknown as Record<string, unknown>;
  const nextRecord = next as unknown as Record<string, unknown>;

  for (const field of SAFE_ASSISTANT_SCALARS[stage]) {
    const existing = currentRecord[field];
    const proposed = patchRecord[field];
    const explicitlyReplaceQuery = stage === 'query' && field === 'query_text';
    if (
      typeof existing === 'string'
      && (explicitlyReplaceQuery || !existing.trim())
      && typeof proposed === 'string'
      && proposed.trim()
    ) {
      nextRecord[field] = proposed.trim();
    }
  }

  for (const field of SAFE_ASSISTANT_ARRAYS[stage]) {
    const existing = Array.isArray(currentRecord[field])
      ? currentRecord[field].filter((value): value is string => typeof value === 'string')
      : [];
    const proposed = Array.isArray(patchRecord[field])
      ? patchRecord[field].filter((value): value is string => typeof value === 'string')
      : [];
    const combined = unique([...existing, ...proposed]);
    nextRecord[field] = field === 'technique_ids'
      ? combined.map(value => value.toUpperCase()).filter(value => /^T\d{4}(?:\.\d{3})?$/.test(value))
      : combined;
  }

  if (
    (stage === 'hypothesis' || stage === 'query')
    && typeof patch.query_language === 'string'
    && THREAT_HUNT_QUERY_LANGUAGES.includes(patch.query_language as ThreatHuntQueryLanguage)
    && (
      stage === 'query'
      || (current.query_language === 'generic' && !current.query_text.trim())
    )
  ) {
    next.query_language = patch.query_language as ThreatHuntQueryLanguage;
  }

  return next;
}

function emptyHunt(owner: string): ThreatHuntInput {
  return {
    title: '',
    hypothesis: '',
    description: '',
    scope: '',
    status: 'draft',
    priority: 'P3 Monitor',
    owner,
    tlp: 'TLP:AMBER',
    technique_ids: [],
    tactics: [],
    telemetry_sources: [],
    required_fields: [],
    tags: [],
    query_language: 'generic',
    query_text: '',
    time_range_start: null,
    time_range_end: null,
    expected_evidence: '',
    false_positive_notes: '',
    assumptions: '',
    result_summary: '',
    disposition: 'undetermined',
  };
}

function toInput(hunt: ThreatHunt | ThreatHuntDetail): ThreatHuntInput {
  return {
    title: hunt.title,
    hypothesis: hunt.hypothesis,
    description: hunt.description,
    scope: hunt.scope,
    status: hunt.status,
    priority: hunt.priority,
    owner: hunt.owner,
    tlp: hunt.tlp,
    technique_ids: hunt.technique_ids,
    tactics: hunt.tactics,
    telemetry_sources: hunt.telemetry_sources,
    required_fields: hunt.required_fields,
    tags: hunt.tags,
    query_language: hunt.query_language,
    query_text: hunt.query_text,
    time_range_start: hunt.time_range_start,
    time_range_end: hunt.time_range_end,
    expected_evidence: hunt.expected_evidence,
    false_positive_notes: hunt.false_positive_notes,
    assumptions: hunt.assumptions,
    result_summary: hunt.result_summary,
    disposition: hunt.disposition,
  };
}

function applyTemplate(current: ThreatHuntInput, template: ThreatHuntTemplate): ThreatHuntInput {
  return {
    ...current,
    title: template.title,
    hypothesis: template.hypothesis,
    description: template.description,
    technique_ids: unique([...current.technique_ids, ...template.technique_ids]),
    tactics: unique([...current.tactics, ...template.tactics]),
    telemetry_sources: unique([...current.telemetry_sources, ...template.telemetry_sources]),
    required_fields: unique([...current.required_fields, ...template.required_fields]),
    query_language: template.query_language as ThreatHuntQueryLanguage,
    query_text: template.query_text,
    expected_evidence: template.expected_evidence,
    false_positive_notes: template.false_positive_notes,
    tags: unique([...current.tags, ...template.tags, `template:${template.id}`]),
  };
}

function templateWouldOverwriteDraft(current: ThreatHuntInput, template: ThreatHuntTemplate) {
  const scalarPairs: Array<[string, string]> = [
    [current.title, template.title],
    [current.hypothesis, template.hypothesis],
    [current.description, template.description],
    [current.query_text, template.query_text],
    [current.expected_evidence, template.expected_evidence],
    [current.false_positive_notes, template.false_positive_notes],
  ];
  if (current.query_language !== 'generic' && current.query_language !== template.query_language) return true;
  return scalarPairs.some(([existing, proposed]) => Boolean(existing.trim()) && existing !== proposed);
}

function draftFingerprint(draft: ThreatHuntInput) {
  return JSON.stringify(draft);
}

function useUnsavedChangesGuard(dirty: boolean) {
  const dirtyRef = useRef(dirty);
  const allowNextNavigation = useRef(false);

  useEffect(() => {
    dirtyRef.current = dirty;
  }, [dirty]);

  const confirmDiscard = useCallback(() => {
    if (!dirtyRef.current) return true;
    const accepted = window.confirm('Discard unsaved threat-hunt changes and leave this workspace?');
    if (accepted) {
      allowNextNavigation.current = true;
      window.setTimeout(() => {
        allowNextNavigation.current = false;
      }, 1000);
    }
    return accepted;
  }, []);

  useEffect(() => {
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (!dirtyRef.current || allowNextNavigation.current) return;
      event.preventDefault();
      event.returnValue = '';
    };
    const captureNavigation = (event: MouseEvent) => {
      if (!dirtyRef.current || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const target = event.target;
      if (!(target instanceof Element)) return;
      const anchor = target.closest<HTMLAnchorElement>('a[href]');
      if (!anchor || anchor.hasAttribute('download') || (anchor.target && anchor.target !== '_self')) return;
      const destination = new URL(anchor.href, window.location.href);
      if (destination.pathname === window.location.pathname && destination.search === window.location.search) return;
      if (confirmDiscard()) return;
      event.preventDefault();
      event.stopPropagation();
    };

    window.addEventListener('beforeunload', beforeUnload);
    document.addEventListener('click', captureNavigation, true);
    return () => {
      window.removeEventListener('beforeunload', beforeUnload);
      document.removeEventListener('click', captureNavigation, true);
    };
  }, [confirmDiscard]);

  return confirmDiscard;
}

function normalize(input: ThreatHuntInput): ThreatHuntInput {
  return {
    ...input,
    title: input.title.trim(),
    hypothesis: input.hypothesis.trim(),
    owner: input.owner.trim(),
    technique_ids: unique(input.technique_ids.map(value => value.toUpperCase())),
    tactics: unique(input.tactics),
    telemetry_sources: unique(input.telemetry_sources),
    required_fields: unique(input.required_fields),
    tags: unique(input.tags),
  };
}

function validate(input: ThreatHuntInput, status: ThreatHuntStatus) {
  if (input.title.trim().length < 3) return 'Add a hunt title with at least three characters.';
  if (input.hypothesis.trim().length < 10) return 'Write a falsifiable hunt hypothesis with at least ten characters.';
  const invalidTechniques = input.technique_ids.filter(value => !/^T\d{4}(?:\.\d{3})?$/.test(value.toUpperCase()));
  if (invalidTechniques.length) return `Correct invalid ATT&CK technique IDs: ${invalidTechniques.join(', ')}.`;
  if (input.time_range_start && input.time_range_end && new Date(input.time_range_end) <= new Date(input.time_range_start)) return 'The hunt end time must be later than the start time.';
  if (!['queued', 'draft', 'archived', 'cancelled'].includes(status)) {
    if (!input.scope.trim()) return 'Define the hunt scope before moving it into the active lifecycle.';
    if (!input.telemetry_sources.length) return 'Select at least one telemetry source before moving it into the active lifecycle.';
    if (!input.expected_evidence.trim()) return 'Define expected evidence before moving it into the active lifecycle.';
    if (!input.false_positive_notes.trim()) return 'Document false-positive considerations before moving it into the active lifecycle.';
  }
  if (status === 'completed') {
    if (input.disposition === 'undetermined') return 'Select a reviewed disposition before completing the hunt.';
    if (input.result_summary.trim().length < 20) return 'Add a result summary before completing the hunt.';
  }
  return '';
}

function readinessChecks(input: ThreatHuntInput) {
  return [
    { label: 'Falsifiable hypothesis', ready: input.hypothesis.trim().length >= 10 },
    { label: 'Bounded hunt scope', ready: Boolean(input.scope.trim()) },
    { label: 'ATT&CK context', ready: input.technique_ids.length > 0 },
    { label: 'Telemetry sources', ready: input.telemetry_sources.length > 0 },
    { label: 'Expected evidence', ready: Boolean(input.expected_evidence.trim()) },
    { label: 'False-positive review', ready: Boolean(input.false_positive_notes.trim()) },
  ];
}

function completionChecks(input: ThreatHuntInput, findings: ThreatHuntDetail['findings']) {
  const reviewed = findings.every(finding => finding.status !== 'new');
  const supporting = findings.some(finding => (
    finding.verdict === 'supports' && ['reviewed', 'escalated', 'closed'].includes(finding.status)
  ));
  const evidenceRequired = ['suspicious', 'confirmed_malicious'].includes(input.disposition);
  return [
    { label: 'Outcome selected', ready: input.disposition !== 'undetermined' },
    { label: 'Result summary', ready: input.result_summary.trim().length >= 20 },
    { label: 'All findings reviewed', ready: reviewed },
    { label: 'Supporting evidence for outcome', ready: !evidenceRequired || supporting },
    { label: 'Known limitations', ready: Boolean(input.assumptions.trim()) },
  ];
}

function validateCompletion(input: ThreatHuntInput, findings: ThreatHuntDetail['findings']) {
  if (!input.assumptions.trim()) return 'Document known limitations before completing the hunt.';
  if (findings.some(finding => finding.status === 'new')) return 'Review or archive every new finding before completing the hunt.';
  const canCompleteWithoutFinding = ['no_matches', 'telemetry_gap', 'query_failure', 'inconclusive'].includes(input.disposition);
  if (!findings.length && !canCompleteWithoutFinding) return 'Record a reviewed finding for this disposition before completing the hunt.';
  if (
    ['suspicious', 'confirmed_malicious'].includes(input.disposition)
    && !findings.some(finding => (
      finding.verdict === 'supports' && ['reviewed', 'escalated', 'closed'].includes(finding.status)
    ))
  ) return 'Suspicious or malicious outcomes require a reviewed finding that supports the hypothesis.';
  return '';
}

function Readiness({ checks, compact = false }: { checks: Array<{ label: string; ready: boolean }>; compact?: boolean }) {
  const ready = checks.filter(item => item.ready).length;
  return (
    <section className={compact ? '' : 'h-fit rounded border border-gray-800 bg-gray-950/60 p-4'}>
      {!compact && <><h2 className="text-sm font-semibold text-white">Plan readiness</h2><p className="mt-1 text-xs text-gray-600">{ready}/{checks.length} controls documented</p></>}
      <div className={`${compact ? '' : 'mt-4'} space-y-2`}>
        {checks.map(item => (
          <div key={item.label} className="flex items-center justify-between gap-3 rounded border border-gray-800 bg-gray-900/60 px-3 py-2 text-xs">
            <span className="text-gray-400">{item.label}</span>
            <span className={item.ready ? 'text-emerald-300' : 'text-amber-300'}>{item.ready ? 'Ready' : 'Required'}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function ListField({ label, values, onChange, placeholder, mono = false, wide = false }: { label: string; values: string[]; onChange: (values: string[]) => void; placeholder: string; mono?: boolean; wide?: boolean }) {
  const [text, setText] = useState(values.join(', '));
  const valuesKey = values.join('\u0000');
  useEffect(() => setText(valuesKey ? valuesKey.split('\u0000').join(', ') : ''), [valuesKey]);
  return (
    <Field label={label} wide={wide}>
      <input
        className={`field ${mono ? 'font-mono' : ''}`}
        value={text}
        onChange={event => setText(event.target.value)}
        onBlur={() => onChange(splitList(text))}
        placeholder={placeholder}
      />
    </Field>
  );
}

function Field({ label, children, required = false, wide = false }: { label: string; children: React.ReactNode; required?: boolean; wide?: boolean }) {
  return <label className={`text-xs text-gray-500 ${wide ? 'lg:col-span-2' : ''}`}>{label}{required && <span className="ml-1 text-red-400">*</span>}<div className="mt-1">{children}</div></label>;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="overflow-hidden rounded border border-gray-800 bg-gray-950/50"><h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>{children}</section>;
}

function QueryHistory({ versions }: { versions: ThreatHuntQueryVersion[] }) {
  return (
    <Panel title="Append-only query history">
      <div className="max-h-52 overflow-y-auto">
        {versions.map(version => (
          <details key={version.id} className="border-b border-gray-800 last:border-b-0">
            <summary className="cursor-pointer px-4 py-3 text-xs text-gray-300">
              <span className="font-semibold text-cyan-200">v{version.version}</span>
              <span className="ml-2">{version.language}</span>
              <span className="ml-2 font-mono text-[10px] text-gray-600">sha256:{version.checksum.slice(0, 12)}…</span>
            </summary>
            <div className="space-y-2 border-t border-gray-800 bg-gray-950 px-4 py-3">
              <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-words text-[10px] leading-4 text-gray-400">{version.query_text || 'Empty query revision'}</pre>
              <p className="text-[10px] text-gray-600">{version.created_by} · {formatDate(version.created_at)}</p>
            </div>
          </details>
        ))}
      </div>
    </Panel>
  );
}

function ReadOnlyNotice({ status }: { status: ThreatHuntStatus }) {
  return (
    <div role="status" className="rounded border border-gray-700 bg-gray-950 px-4 py-3 text-xs leading-5 text-gray-400">
      This hunt is <b className="text-gray-200">{status}</b> and its plan is read-only. Completed and cancelled hunts can still be archived; exports and defensive handoff links remain available.
    </div>
  );
}

function WorkspaceState({ text, onBack, error = false }: { text: string; onBack: () => void; error?: boolean }) {
  return <main className="flex-1 px-6 py-10"><div className={`mx-auto max-w-2xl rounded border p-8 text-center text-sm ${error ? 'border-red-800 bg-red-950/20 text-red-200' : 'border-gray-800 text-gray-500'}`}><p>{text}</p><button type="button" className="secondary-action mt-4" onClick={onBack}>Return to hunt queue</button></div></main>;
}

function unique(values: string[]) {
  return Array.from(new Set(values.map(value => value.trim()).filter(Boolean)));
}

function tlpsAtLeast(parent: ThreatHuntTlp) {
  const index = TLP_OPTIONS.indexOf(parent);
  return index < 0 ? TLP_OPTIONS : TLP_OPTIONS.slice(index);
}

function splitList(value: string) {
  return unique(value.split(/[\n,]/));
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

function editorLanguage(language: ThreatHuntQueryLanguage) {
  if (language === 'sql') return 'sql';
  if (language === 'yara') return 'plaintext';
  return 'plaintext';
}

async function copyText(value: string) {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(value);
  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand('copy');
  textarea.remove();
  if (!copied) throw new Error('Copy is not available');
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : error ? String(error) : '';
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString();
}
