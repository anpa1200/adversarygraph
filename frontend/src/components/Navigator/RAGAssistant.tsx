import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';

import { ragApi } from '@/api/client';
import { PermissionNotice } from '@/components/PermissionNotice';
import {
  Dialog,
  DialogBody,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from '@/components/ui/dialog';
import { useHasPermission } from '@/hooks/useCurrentUser';

type ApplyMode = 'add' | 'replace';
type RequestKind = 'search' | 'assist';
type SourceFilter = 'ioc' | 'cve' | 'technique' | 'actor' | 'report' | 'asset';

export interface RAGAssistantProps {
  domain: string;
  attackVersion: string | null;
  selectedTechniques: Set<string>;
  onPreview: (techniqueIds: string[] | null) => void;
  onApply: (techniqueIds: string[], mode: ApplyMode) => void;
}

interface ProviderStatus {
  id: string;
  label: string;
  model: string;
  configured: boolean;
  available: boolean;
  status: string;
  reason: string;
  remote: boolean;
  isDefault: boolean;
}

interface RAGStatus {
  ready?: boolean;
  indexStatus: string;
  documentCount?: number;
  chunkCount?: number;
  retrievalMode: string;
  defaultResultLimit: number;
  warnings: string[];
  providers: ProviderStatus[];
}

interface RAGCitation {
  sourceRef: string;
  sourceType: string;
  title: string;
  excerpt: string;
  route: string;
  tlp: string;
  legalSensitive: boolean;
  score?: number;
  verified: boolean;
}

interface RAGEntity {
  sourceType: string;
  sourceId: string;
  title: string;
  route: string;
  metadata: Record<string, unknown>;
}

interface NavigatorProposal {
  id: string;
  name: string;
  domain: string;
  attackVersion: string;
  techniqueIds: string[];
  rationale: string;
  checksum: string;
  expiresAt: string;
  requiresConfirmation: boolean;
}

interface RAGResult {
  assistanceId: string;
  answer: string;
  retrievalMode: string;
  effectiveTlp: string;
  citations: RAGCitation[];
  entities: RAGEntity[];
  warnings: string[];
  proposal: NavigatorProposal | null;
}

const SOURCE_OPTIONS: Array<{ id: SourceFilter; label: string; description: string }> = [
  { id: 'ioc', label: 'IOCs', description: 'Indicators and observables' },
  { id: 'cve', label: 'CVEs', description: 'Vulnerabilities and affected products' },
  { id: 'technique', label: 'TTPs', description: 'ATT&CK and ATLAS techniques' },
  { id: 'actor', label: 'Actors', description: 'Threat groups and campaigns' },
  { id: 'report', label: 'Reports', description: 'Stored reports and research' },
  { id: 'asset', label: 'Assets', description: 'Sanitized asset and exposure context' },
];

const SOURCE_TYPE_MAP: Record<SourceFilter, string[]> = {
  ioc: ['ioc'],
  cve: ['cve'],
  technique: ['attack_technique'],
  actor: ['attack_group', 'attack_campaign', 'actor_intel'],
  report: ['analysis_report', 'knowledge', 'threat_signal', 'threat_hunt', 'evidence_node'],
  asset: ['asset'],
};

const FALLBACK_PROVIDERS: ProviderStatus[] = [
  {
    id: 'local',
    label: 'Local',
    model: '',
    configured: true,
    available: true,
    status: 'ready',
    reason: 'Configured and available.',
    remote: false,
    isDefault: true,
  },
  {
    id: 'claude',
    label: 'Claude',
    model: '',
    configured: true,
    available: true,
    status: 'ready',
    reason: 'Configured and available.',
    remote: true,
    isDefault: false,
  },
  {
    id: 'openai',
    label: 'OpenAI',
    model: '',
    configured: true,
    available: true,
    status: 'ready',
    reason: 'Configured and available.',
    remote: true,
    isDefault: false,
  },
  {
    id: 'gemini',
    label: 'Gemini',
    model: '',
    configured: true,
    available: true,
    status: 'ready',
    reason: 'Configured and available.',
    remote: true,
    isDefault: false,
  },
  {
    id: 'minimax',
    label: 'MiniMax',
    model: '',
    configured: true,
    available: true,
    status: 'ready',
    reason: 'Configured and available.',
    remote: true,
    isDefault: false,
  },
];

const DEFAULT_SOURCE_FILTERS = new Set<SourceFilter>(SOURCE_OPTIONS.map(option => option.id));

export function RAGAssistant({
  domain,
  attackVersion,
  selectedTechniques,
  onPreview,
  onApply,
}: RAGAssistantProps) {
  const canRunAnalysis = useHasPermission('run_analysis');
  const canManageFeeds = useHasPermission('manage_feeds');
  const canManageIntel = useHasPermission('manage_intel');
  const [open, setOpen] = useState(false);
  const [prompt, setPrompt] = useState('');
  const [providerId, setProviderId] = useState('local');
  const [clientProfileId, setClientProfileId] = useState('');
  const [profileEditorOpen, setProfileEditorOpen] = useState(false);
  const [profileName, setProfileName] = useState('');
  const [profileSector, setProfileSector] = useState('');
  const [profileRegion, setProfileRegion] = useState('');
  const [profileTechnologies, setProfileTechnologies] = useState('');
  const [profileCrownJewels, setProfileCrownJewels] = useState('');
  const [profileSaving, setProfileSaving] = useState(false);
  const [sourceFilters, setSourceFilters] = useState<Set<SourceFilter>>(
    () => new Set(DEFAULT_SOURCE_FILTERS),
  );
  const [cloudAcknowledged, setCloudAcknowledged] = useState(false);
  const [pending, setPending] = useState<RequestKind | null>(null);
  const [resultKind, setResultKind] = useState<RequestKind | null>(null);
  const [result, setResult] = useState<RAGResult | null>(null);
  const [requestError, setRequestError] = useState('');
  const [notice, setNotice] = useState('');
  const [previewedProposalId, setPreviewedProposalId] = useState('');
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const [applyMode, setApplyMode] = useState<ApplyMode>('add');
  const [evidenceReviewed, setEvidenceReviewed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [reindexing, setReindexing] = useState(false);
  const [appliedProposalId, setAppliedProposalId] = useState('');
  const [, setClockTick] = useState(0);

  const requestSequence = useRef(0);
  const confirmationSequence = useRef(0);
  const previewActive = useRef(false);
  const resultRef = useRef<RAGResult | null>(null);
  const onPreviewRef = useRef(onPreview);
  const onApplyRef = useRef(onApply);

  onPreviewRef.current = onPreview;
  onApplyRef.current = onApply;
  resultRef.current = result;

  const statusQuery = useQuery({
    queryKey: ['rag-status'],
    queryFn: async () => normalizeStatus(await ragApi.status()),
    enabled: canRunAnalysis && open,
    staleTime: 30_000,
    refetchInterval: open ? 15_000 : false,
    retry: 1,
  });
  const profilesQuery = useQuery({
    queryKey: ['rag-client-profiles'],
    queryFn: ragApi.profiles,
    enabled: canRunAnalysis && open,
    staleTime: 60_000,
    retry: 1,
  });

  const status = statusQuery.data;
  const providers = status?.providers.length ? status.providers : FALLBACK_PROVIDERS;
  const selectedProvider = providers.find(provider => provider.id === providerId);
  const sourceFilterKey = useMemo(
    () => [...sourceFilters].sort().join(','),
    [sourceFilters],
  );
  const requestFingerprint = useMemo(
    () => JSON.stringify({
      query: prompt.trim(),
      provider: providerId,
      domain: normalizeDomain(domain),
      attackVersion,
      clientProfileId: clientProfileId.trim(),
      sourceTypes: sourceFilterKey,
    }),
    [attackVersion, clientProfileId, domain, prompt, providerId, sourceFilterKey],
  );
  const fingerprintRef = useRef(requestFingerprint);
  const selectedFingerprint = useMemo(
    () => [...selectedTechniques].map(normalizeTechniqueId).sort().join(','),
    [selectedTechniques],
  );
  const selectedFingerprintRef = useRef(selectedFingerprint);

  const clearPreview = useCallback(() => {
    if (previewActive.current) onPreviewRef.current(null);
    previewActive.current = false;
    setPreviewedProposalId('');
  }, []);

  useEffect(() => {
    if (!providers.length) return;
    const current = providers.find(provider => provider.id === providerId);
    if (current?.available) return;
    const next = providers.find(provider => provider.isDefault && provider.available)
      ?? providers.find(provider => !provider.remote && provider.available)
      ?? providers.find(provider => provider.available);
    if (next && next.id !== providerId) setProviderId(next.id);
  }, [providerId, providers]);

  useEffect(() => {
    if (fingerprintRef.current === requestFingerprint) return;
    const hadReviewState = Boolean(
      resultRef.current || previewActive.current || confirmationOpen || appliedProposalId,
    );
    fingerprintRef.current = requestFingerprint;
    requestSequence.current += 1;
    confirmationSequence.current += 1;
    setPending(null);
    setConfirming(false);
    setResult(null);
    setResultKind(null);
    setRequestError('');
    setConfirmationOpen(false);
    setEvidenceReviewed(false);
    setAppliedProposalId('');
    setCloudAcknowledged(false);
    clearPreview();
    if (hadReviewState) {
      setNotice('Previous results and preview were cleared because the request context changed.');
    }
  }, [appliedProposalId, clearPreview, confirmationOpen, requestFingerprint]);

  useEffect(() => {
    if (selectedFingerprintRef.current === selectedFingerprint) return;
    selectedFingerprintRef.current = selectedFingerprint;
    if (confirmationOpen) {
      setEvidenceReviewed(false);
      setNotice('Navigator selection changed. Review the updated Add/Replace diff before confirming.');
    }
  }, [confirmationOpen, selectedFingerprint]);

  useEffect(() => {
    if (!result?.proposal?.expiresAt) return undefined;
    const timer = window.setInterval(() => setClockTick(value => value + 1), 15_000);
    return () => window.clearInterval(timer);
  }, [result?.proposal?.expiresAt]);

  useEffect(() => () => {
    requestSequence.current += 1;
    confirmationSequence.current += 1;
    if (previewActive.current) onPreviewRef.current(null);
  }, []);

  if (!canRunAnalysis) {
    return (
      <PermissionNotice
        permission="run_analysis"
        action="search intelligence with the RAG assistant"
        compact
      />
    );
  }

  const indexReady = !statusQuery.isLoading && !statusQuery.isError && status?.ready !== false;
  const providerAvailable = Boolean(selectedProvider?.available);
  const remoteProvider = Boolean(selectedProvider?.remote);
  const hasSources = sourceFilters.size > 0;
  const hasPrompt = Boolean(prompt.trim());
  const normalizedClientProfileId = clientProfileId.trim();
  const parsedClientProfileId = Number(normalizedClientProfileId);
  const clientProfileValid = !normalizedClientProfileId || (
    /^[1-9]\d*$/.test(normalizedClientProfileId)
    && Number.isSafeInteger(parsedClientProfileId)
    && Number(parsedClientProfileId) > 0
  );
  const canSearch = hasPrompt && hasSources && clientProfileValid && indexReady && !pending && !confirming;
  const canAssist = canSearch
    && providerAvailable
    && (!remoteProvider || cloudAcknowledged);

  const toggleSource = (source: SourceFilter) => {
    setSourceFilters(current => {
      const next = new Set(current);
      if (next.has(source)) next.delete(source);
      else next.add(source);
      return next;
    });
  };

  const queueInitialIndex = async () => {
    if (!canManageFeeds || reindexing) return;
    setReindexing(true);
    setRequestError('');
    try {
      const queued = await ragApi.reindex({ source_types: [], include_embeddings: true });
      setNotice(`RAG reconciliation ${queued.run_id.slice(0, 12)} queued. Status refreshes every 15 seconds.`);
      await statusQuery.refetch();
    } catch (error) {
      setRequestError(errorMessage(error));
    } finally {
      setReindexing(false);
    }
  };

  const createBusinessProfile = async () => {
    if (!canManageIntel || profileSaving || !profileName.trim() || !profileSector.trim()) return;
    setProfileSaving(true);
    setRequestError('');
    try {
      const created = await ragApi.createProfile({
        name: profileName.trim(),
        sector: profileSector.trim(),
        region: profileRegion.trim(),
        technologies: splitProfileTerms(profileTechnologies),
        crown_jewels: splitProfileTerms(profileCrownJewels),
      });
      setClientProfileId(String(created.id));
      setProfileName('');
      setProfileSector('');
      setProfileRegion('');
      setProfileTechnologies('');
      setProfileCrownJewels('');
      setProfileEditorOpen(false);
      setNotice(`Business profile “${created.name}” created and selected.`);
      await profilesQuery.refetch();
    } catch (error) {
      setRequestError(errorMessage(error));
    } finally {
      setProfileSaving(false);
    }
  };

  const runRequest = async (kind: RequestKind) => {
    if ((kind === 'search' && !canSearch) || (kind === 'assist' && !canAssist)) return;
    const query = prompt.trim();
    const requestedFingerprint = requestFingerprint;
    const sequence = requestSequence.current + 1;
    requestSequence.current = sequence;
    confirmationSequence.current += 1;
    setPending(kind);
    setRequestError('');
    setNotice('');
    setResult(null);
    setResultKind(null);
    setConfirmationOpen(false);
    setEvidenceReviewed(false);
    setAppliedProposalId('');
    clearPreview();

    const searchPayload = {
      query,
      domain,
      attack_version: attackVersion ?? undefined,
      client_profile_id: normalizedClientProfileId ? parsedClientProfileId : undefined,
      source_types: Array.from(new Set(
        [...sourceFilters].flatMap(source => SOURCE_TYPE_MAP[source]),
      )).sort(),
      limit: status?.defaultResultLimit ?? 12,
    };

    try {
      const response = kind === 'search'
        ? await ragApi.search(searchPayload as Parameters<typeof ragApi.search>[0])
        : await ragApi.assist({
          ...searchPayload,
          provider: providerId,
          model: selectedProvider?.model || undefined,
          cloud_processing_acknowledged: remoteProvider ? cloudAcknowledged : false,
        } as Parameters<typeof ragApi.assist>[0]);
      if (
        sequence !== requestSequence.current
        || requestedFingerprint !== fingerprintRef.current
      ) return;
      const normalized = normalizeResult(response);
      setResult(normalized);
      setResultKind(kind);
      setNotice(kind === 'search'
        ? 'Evidence search complete. No Navigator selection was changed.'
        : 'Grounded assistance complete. Review citations before using any proposal.');
    } catch (error) {
      if (sequence !== requestSequence.current) return;
      setRequestError(errorMessage(error));
    } finally {
      if (sequence === requestSequence.current) setPending(null);
    }
  };

  const proposal = result?.proposal ?? null;
  const proposalIds = proposal?.techniqueIds ?? [];
  const invalidTechniqueIds = proposalIds.filter(id => !isTechniqueId(id));
  const proposalDomainMismatch = Boolean(
    proposal?.domain && normalizeDomain(proposal.domain) !== normalizeDomain(domain),
  );
  const proposalVersionMismatch = Boolean(
    proposal
    && (!attackVersion || proposal.attackVersion !== attackVersion),
  );
  const proposalExpired = Boolean(
    proposal && (!proposal.expiresAt || isExpired(proposal.expiresAt)),
  );
  const proposalGrounded = Boolean(
    result?.citations.length && result.citations.every(citation => citation.verified),
  );
  const proposalBlocked = invalidTechniqueIds.length > 0
    || proposalDomainMismatch
    || proposalVersionMismatch
    || proposalExpired
    || proposalIds.length === 0
    || !proposal?.id
    || !isUuid(proposal.id)
    || !proposal.checksum
    || !isChecksum(proposal.checksum)
    || !proposal.attackVersion
    || !proposalGrounded;
  const diff = buildSelectionDiff(selectedTechniques, proposalIds, applyMode);

  const previewProposal = () => {
    if (!proposal || proposalBlocked) {
      setRequestError('This proposal cannot be previewed because it failed local validation.');
      return;
    }
    onPreviewRef.current(proposalIds);
    previewActive.current = true;
    setPreviewedProposalId(proposal.id);
    setNotice(`Previewing ${proposalIds.length} proposed technique${proposalIds.length === 1 ? '' : 's'} as a temporary overlay. Your selection is unchanged.`);
    setOpen(false);
  };

  const beginConfirmation = () => {
    if (!proposal || proposalBlocked || appliedProposalId === proposal.id) return;
    setApplyMode('add');
    setEvidenceReviewed(false);
    setRequestError('');
    setConfirmationOpen(true);
  };

  const confirmProposal = async () => {
    if (
      !proposal
      || proposalBlocked
      || !evidenceReviewed
      || !result?.citations.length
      || confirming
    ) return;
    if (proposal.expiresAt && isExpired(proposal.expiresAt)) {
      setRequestError('The proposal expired. Run the grounded assistant again.');
      return;
    }

    const sequence = confirmationSequence.current + 1;
    confirmationSequence.current = sequence;
    const requestedFingerprint = requestFingerprint;
    const requestedSelection = selectedFingerprint;
    const proposalId = proposal.id;
    setConfirming(true);
    setRequestError('');
    setNotice('');

    try {
      const confirmation = await ragApi.confirmProposal(
        proposal.id,
        { checksum: proposal.checksum, mode: applyMode } as Parameters<typeof ragApi.confirmProposal>[1],
      );
      const confirmationPayload = asRecord(confirmation);
      const confirmationStatus = stringValue(confirmationPayload.status);
      const confirmedIds = uniqueStrings(confirmationPayload.technique_ids).map(normalizeTechniqueId);
      if (confirmationStatus !== 'confirmed') {
        throw new Error('The server did not return an exact confirmed proposal receipt.');
      }
      if (stringValue(confirmationPayload.proposal_id) !== proposal.id) {
        throw new Error('The server-confirmed proposal ID differs from the reviewed proposal.');
      }
      if (stringValue(confirmationPayload.mode) !== applyMode) {
        throw new Error('The server-confirmed apply mode differs from the reviewed action.');
      }
      if (normalizeDomain(stringValue(confirmationPayload.domain)) !== normalizeDomain(domain)) {
        throw new Error('The server-confirmed domain differs from the active Navigator domain.');
      }
      if (stringValue(confirmationPayload.attack_version) !== proposal.attackVersion) {
        throw new Error('The server-confirmed ATT&CK version differs from the reviewed proposal.');
      }
      if (confirmationPayload.persisted !== false) {
        throw new Error('The server receipt did not preserve the non-persistent proposal boundary.');
      }
      if (!confirmedIds.length || !sameStringSet(confirmedIds, proposal.techniqueIds)) {
        throw new Error('The server-confirmed technique set differs from the reviewed proposal. No local change was applied.');
      }
      const currentProposal = resultRef.current?.proposal;
      if (
        sequence !== confirmationSequence.current
        || requestedFingerprint !== fingerprintRef.current
        || requestedSelection !== selectedFingerprintRef.current
        || currentProposal?.id !== proposalId
      ) {
        setRequestError('The proposal or Navigator selection changed during confirmation. No local change was applied.');
        return;
      }
      onApplyRef.current(confirmedIds, applyMode);
      clearPreview();
      setAppliedProposalId(proposal.id);
      setConfirmationOpen(false);
      setEvidenceReviewed(false);
      setNotice(
        `${applyMode === 'add' ? 'Added' : 'Replaced the selection with'} ${proposal.techniqueIds.length} server-verified technique${proposal.techniqueIds.length === 1 ? '' : 's'}. Save a named layer separately if required.`,
      );
    } catch (error) {
      if (sequence === confirmationSequence.current) setRequestError(errorMessage(error));
    } finally {
      if (sequence === confirmationSequence.current) setConfirming(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        type="button"
        className="secondary-action border-cyan-800/80 text-cyan-200 hover:border-cyan-500"
        onClick={() => setOpen(true)}
      >
        {result?.proposal ? 'Review AI proposal' : 'AI RAG assistant'}
      </button>
      {previewedProposalId && (
        <button
          type="button"
          className="secondary-action border-amber-800/80 text-amber-200"
          onClick={() => {
            clearPreview();
            setNotice('Temporary AI proposal preview cleared.');
          }}
        >
          Clear AI preview
        </button>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="w-[min(96vw,1180px)]">
          <div className="flex items-start justify-between gap-4 border-b border-gray-800 pr-4">
            <div>
              <DialogTitle>Intelligence RAG assistant</DialogTitle>
              <DialogDescription className="pb-3">
                Searches governed AdversaryGraph evidence and can propose a Navigator layer. It never changes the active selection without explicit confirmation.
              </DialogDescription>
            </div>
            <DialogClose asChild>
              <button
                type="button"
                className="mt-3 rounded border border-gray-700 px-2 py-1 text-xs text-gray-400 hover:text-white"
              >
                Close
              </button>
            </DialogClose>
          </div>

          <DialogBody className="max-h-[78vh]">
            <div className="grid gap-5 lg:grid-cols-[350px_minmax(0,1fr)]">
              <div className="space-y-4">
                <section className="rounded border border-cyan-900/70 bg-cyan-950/20 p-3 text-xs leading-5 text-cyan-100/80">
                  <b className="block text-cyan-100">Evidence before action</b>
                  Retrieved content and AI output are investigative leads, not proof. Review source excerpts and validate relevance before applying a TTP proposal.
                </section>

                <IndexStatusCard
                  status={status}
                  loading={statusQuery.isLoading}
                  error={statusQuery.error}
                />
                {status?.ready === false && canManageFeeds && (
                  <button
                    type="button"
                    className="secondary-action w-full disabled:cursor-not-allowed disabled:opacity-40"
                    disabled={reindexing}
                    onClick={() => void queueInitialIndex()}
                  >
                    {reindexing ? 'Queuing reconciliation…' : 'Build / refresh RAG index'}
                  </button>
                )}

                <label className="block text-xs text-gray-500">
                  AI provider
                  <select
                    aria-label="RAG AI provider"
                    className="field mt-1"
                    value={providerId}
                    disabled={Boolean(pending) || confirming || statusQuery.isLoading}
                    onChange={event => setProviderId(event.target.value)}
                  >
                    {providers.map(provider => (
                      <option key={provider.id} value={provider.id} disabled={!provider.available}>
                        {provider.label}{provider.model ? ` · ${provider.model}` : ''}{provider.remote ? ' · remote' : ' · local'}{!provider.available ? ` · ${providerStatusLabel(provider.status)}` : ''}
                      </option>
                    ))}
                  </select>
                </label>
                {selectedProvider && !selectedProvider.available && (
                  <p role="status" className="rounded border border-amber-800/60 bg-amber-950/20 px-3 py-2 text-xs leading-5 text-amber-100">
                    <b className="block">{selectedProvider.label}: {providerStatusLabel(selectedProvider.status)}</b>
                    {selectedProvider.reason}
                  </p>
                )}

                <label className="block text-xs text-gray-500">
                  Business profile <span className="text-gray-700">(optional)</span>
                  <select
                    aria-label="Business profile"
                    className="field mt-1"
                    value={clientProfileId}
                    disabled={Boolean(pending) || confirming || profilesQuery.isLoading}
                    onChange={event => setClientProfileId(event.target.value)}
                  >
                    <option value="">Prompt context only</option>
                    {(profilesQuery.data ?? []).map(profile => (
                      <option key={profile.id} value={profile.id}>
                        {profile.name} · {profile.sector}{profile.region ? ` · ${profile.region}` : ''}
                      </option>
                    ))}
                  </select>
                  <span className="mt-1 block text-[10px] leading-4 text-gray-700">
                    The server loads region, sector, technologies, and crown jewels from the selected saved profile.
                  </span>
                  {profilesQuery.isError && <span role="alert" className="mt-1 block text-xs text-amber-300">Business profiles are unavailable: {errorMessage(profilesQuery.error)}</span>}
                  {!clientProfileValid && <span role="alert" className="mt-1 block text-xs text-amber-300">Enter a positive numeric profile ID.</span>}
                </label>

                {canManageIntel && (
                  <section className="rounded border border-gray-800 bg-gray-950/40 p-3">
                    <button
                      type="button"
                      className="text-xs text-cyan-300 hover:text-cyan-100"
                      disabled={Boolean(pending) || confirming || profileSaving}
                      onClick={() => setProfileEditorOpen(value => !value)}
                    >
                      {profileEditorOpen ? 'Cancel profile creation' : '+ Create business profile'}
                    </button>
                    {profileEditorOpen && (
                      <div className="mt-3 space-y-2">
                        <input
                          aria-label="Business profile name"
                          className="field"
                          value={profileName}
                          maxLength={255}
                          placeholder="Profile name (for example, Israel tech company)"
                          onChange={event => setProfileName(event.target.value)}
                        />
                        <div className="grid grid-cols-2 gap-2">
                          <input
                            aria-label="Business sector"
                            className="field"
                            value={profileSector}
                            maxLength={120}
                            placeholder="Sector (technology)"
                            onChange={event => setProfileSector(event.target.value)}
                          />
                          <input
                            aria-label="Business region"
                            className="field"
                            value={profileRegion}
                            maxLength={120}
                            placeholder="Region (Israel)"
                            onChange={event => setProfileRegion(event.target.value)}
                          />
                        </div>
                        <input
                          aria-label="Business technologies"
                          className="field"
                          value={profileTechnologies}
                          placeholder="Technologies, comma separated"
                          onChange={event => setProfileTechnologies(event.target.value)}
                        />
                        <input
                          aria-label="Business crown jewels"
                          className="field"
                          value={profileCrownJewels}
                          placeholder="Crown jewels, comma separated"
                          onChange={event => setProfileCrownJewels(event.target.value)}
                        />
                        <button
                          type="button"
                          className="secondary-action w-full disabled:cursor-not-allowed disabled:opacity-40"
                          disabled={profileSaving || !profileName.trim() || !profileSector.trim()}
                          onClick={() => void createBusinessProfile()}
                        >
                          {profileSaving ? 'Saving profile…' : 'Save and select profile'}
                        </button>
                      </div>
                    )}
                  </section>
                )}

                <fieldset disabled={Boolean(pending) || confirming}>
                  <legend className="text-xs text-gray-500">Search sources</legend>
                  <div className="mt-2 grid grid-cols-2 gap-2">
                    {SOURCE_OPTIONS.map(option => (
                      <label
                        key={option.id}
                        title={option.description}
                        className={`flex cursor-pointer items-center gap-2 rounded border px-3 py-2 text-xs ${
                          sourceFilters.has(option.id)
                            ? 'border-cyan-800 bg-cyan-950/20 text-cyan-100'
                            : 'border-gray-800 bg-gray-950/50 text-gray-500'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={sourceFilters.has(option.id)}
                          onChange={() => toggleSource(option.id)}
                        />
                        {option.label}
                      </label>
                    ))}
                  </div>
                  {!hasSources && <p role="alert" className="mt-2 text-xs text-amber-300">Select at least one source type.</p>}
                </fieldset>

                <label className="block text-xs text-gray-500">
                  Analyst request
                  <textarea
                    aria-label="RAG analyst request"
                    className="field mt-1 min-h-32 resize-y"
                    value={prompt}
                    maxLength={4000}
                    disabled={Boolean(pending) || confirming}
                    onChange={event => setPrompt(event.target.value)}
                    placeholder="Example: Find IOCs relevant to an Israeli technology company, explain the evidence, and propose only directly supported TTPs."
                  />
                  <span className="mt-1 block text-right text-[10px] text-gray-700">{prompt.length}/4000</span>
                </label>

                {remoteProvider && providerAvailable && (
                  <label className="flex items-start gap-2 rounded border border-amber-800/60 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100">
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={cloudAcknowledged}
                      disabled={Boolean(pending) || confirming}
                      onChange={event => setCloudAcknowledged(event.target.checked)}
                    />
                    <span>
                      I acknowledge that the request and retrieved, policy-eligible source excerpts may be processed by the selected remote provider.
                    </span>
                  </label>
                )}

                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    className="secondary-action min-h-9 disabled:cursor-not-allowed disabled:opacity-40"
                    disabled={!canSearch}
                    onClick={() => void runRequest('search')}
                  >
                    {pending === 'search' ? 'Searching…' : 'Search evidence'}
                  </button>
                  <button
                    type="button"
                    className="primary-action min-h-9 disabled:cursor-not-allowed disabled:opacity-40"
                    disabled={!canAssist}
                    onClick={() => void runRequest('assist')}
                  >
                    {pending === 'assist' ? 'Generating…' : 'Generate grounded answer'}
                  </button>
                </div>
                {pending && (
                  <p role="status" aria-live="polite" className="text-center text-xs text-cyan-200">
                    {pending === 'search' ? 'Searching governed sources…' : 'Retrieving evidence and generating a grounded answer…'} Your Navigator selection remains unchanged.
                  </p>
                )}
                {requestError && (
                  <p role="alert" className="rounded border border-red-800 bg-red-950/30 p-3 text-xs leading-5 text-red-200">
                    {requestError}
                  </p>
                )}
              </div>

              <div className="min-w-0 space-y-4">
                {notice && (
                  <p role="status" aria-live="polite" className="rounded border border-emerald-900/70 bg-emerald-950/20 p-3 text-xs leading-5 text-emerald-100">
                    {notice}
                  </p>
                )}
                {!result && !pending && (
                  <div className="rounded border border-dashed border-gray-800 p-10 text-center text-sm leading-6 text-gray-600">
                    Search the local index for evidence, or generate a cited answer. Any Navigator proposal appears only after the sources it relies on.
                  </div>
                )}
                {result && (
                  <RAGResultView
                    kind={resultKind}
                    result={result}
                    proposal={proposal}
                    proposalIds={proposalIds}
                    proposalDomainMismatch={proposalDomainMismatch}
                    proposalVersionMismatch={proposalVersionMismatch}
                    proposalExpired={proposalExpired}
                    invalidTechniqueIds={invalidTechniqueIds}
                    previewed={previewedProposalId === proposal?.id}
                    applied={appliedProposalId === proposal?.id}
                    confirmationOpen={confirmationOpen}
                    applyMode={applyMode}
                    diff={diff}
                    evidenceReviewed={evidenceReviewed}
                    confirming={confirming}
                    onPreview={previewProposal}
                    onBeginConfirmation={beginConfirmation}
                    onApplyModeChange={mode => {
                      setApplyMode(mode);
                      setEvidenceReviewed(false);
                    }}
                    onEvidenceReviewedChange={setEvidenceReviewed}
                    onCancelConfirmation={() => {
                      setConfirmationOpen(false);
                      setEvidenceReviewed(false);
                    }}
                    onConfirm={() => void confirmProposal()}
                  />
                )}
              </div>
            </div>
          </DialogBody>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function IndexStatusCard({
  status,
  loading,
  error,
}: {
  status: RAGStatus | undefined;
  loading: boolean;
  error: unknown;
}) {
  if (loading) {
    return <p role="status" className="rounded border border-gray-800 bg-gray-950/50 p-3 text-xs text-gray-500">Checking RAG index readiness…</p>;
  }
  if (error) {
    return <p role="alert" className="rounded border border-red-900/70 bg-red-950/20 p-3 text-xs text-red-200">RAG status is unavailable: {errorMessage(error)}</p>;
  }
  if (!status) return null;
  return (
    <section className={`rounded border p-3 text-xs leading-5 ${status.ready === false ? 'border-amber-900/70 bg-amber-950/20 text-amber-100' : 'border-gray-800 bg-gray-950/50 text-gray-400'}`}>
      <div className="flex items-center justify-between gap-3">
        <b className={status.ready === false ? 'text-amber-200' : 'text-gray-200'}>RAG index · {status.indexStatus || (status.ready === false ? 'not ready' : 'ready')}</b>
        {status.retrievalMode && <span className="font-mono text-[10px] text-gray-600">{status.retrievalMode}</span>}
      </div>
      {(status.documentCount != null || status.chunkCount != null) && (
        <p className="mt-1 text-[10px] text-gray-600">
          {status.documentCount ?? '—'} documents · {status.chunkCount ?? '—'} chunks
        </p>
      )}
      {status.warnings.map((warning, index) => (
        <p key={`${warning}-${index}`} className="mt-1 text-amber-200">{warning}</p>
      ))}
    </section>
  );
}

function RAGResultView({
  kind,
  result,
  proposal,
  proposalIds,
  proposalDomainMismatch,
  proposalVersionMismatch,
  proposalExpired,
  invalidTechniqueIds,
  previewed,
  applied,
  confirmationOpen,
  applyMode,
  diff,
  evidenceReviewed,
  confirming,
  onPreview,
  onBeginConfirmation,
  onApplyModeChange,
  onEvidenceReviewedChange,
  onCancelConfirmation,
  onConfirm,
}: {
  kind: RequestKind | null;
  result: RAGResult;
  proposal: NavigatorProposal | null;
  proposalIds: string[];
  proposalDomainMismatch: boolean;
  proposalVersionMismatch: boolean;
  proposalExpired: boolean;
  invalidTechniqueIds: string[];
  previewed: boolean;
  applied: boolean;
  confirmationOpen: boolean;
  applyMode: ApplyMode;
  diff: SelectionDiff;
  evidenceReviewed: boolean;
  confirming: boolean;
  onPreview: () => void;
  onBeginConfirmation: () => void;
  onApplyModeChange: (mode: ApplyMode) => void;
  onEvidenceReviewedChange: (reviewed: boolean) => void;
  onCancelConfirmation: () => void;
  onConfirm: () => void;
}) {
  const proposalBlocked = proposalDomainMismatch
    || proposalVersionMismatch
    || proposalExpired
    || invalidTechniqueIds.length > 0
    || proposalIds.length === 0
    || !proposal?.id
    || !isUuid(proposal.id)
    || !proposal.checksum
    || !isChecksum(proposal.checksum)
    || !proposal.attackVersion
    || !result.citations.length
    || result.citations.some(citation => !citation.verified);
  return (
    <section className="space-y-4" aria-label="RAG intelligence result">
      <div className="rounded border border-cyan-900/60 bg-cyan-950/15 p-3 text-xs leading-5 text-cyan-100/80">
        <div className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10px] text-cyan-200/70">
          <span>{kind === 'search' ? 'evidence search' : 'grounded assistance'}</span>
          {result.assistanceId && <span title={result.assistanceId}>assistance {result.assistanceId.slice(0, 12)}</span>}
          {result.retrievalMode && <span>{result.retrievalMode}</span>}
          {result.effectiveTlp && <span>{result.effectiveTlp}</span>}
        </div>
        <p className="mt-2">No database record, named layer, or Navigator selection was changed by this response.</p>
        {result.warnings.map((warning, index) => (
          <p key={`${warning}-${index}`} className="mt-2 text-amber-200">Warning: {warning}</p>
        ))}
      </div>

      <CitationList citations={result.citations} />

      {result.answer && (
        <section className="rounded border border-gray-800 bg-gray-950/60 p-4">
          <h3 className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">Grounded answer</h3>
          <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-gray-200">{result.answer}</p>
        </section>
      )}

      <EntityList entities={result.entities} />

      {proposal && (
        <ProposalReview
          proposal={proposal}
          proposalIds={proposalIds}
          citationCount={result.citations.length}
          citationsVerified={result.citations.every(citation => citation.verified)}
          proposalDomainMismatch={proposalDomainMismatch}
          proposalVersionMismatch={proposalVersionMismatch}
          proposalExpired={proposalExpired}
          invalidTechniqueIds={invalidTechniqueIds}
          blocked={proposalBlocked}
          previewed={previewed}
          applied={applied}
          confirmationOpen={confirmationOpen}
          applyMode={applyMode}
          diff={diff}
          evidenceReviewed={evidenceReviewed}
          confirming={confirming}
          onPreview={onPreview}
          onBeginConfirmation={onBeginConfirmation}
          onApplyModeChange={onApplyModeChange}
          onEvidenceReviewedChange={onEvidenceReviewedChange}
          onCancelConfirmation={onCancelConfirmation}
          onConfirm={onConfirm}
        />
      )}
    </section>
  );
}

function CitationList({ citations }: { citations: RAGCitation[] }) {
  return (
    <section className="space-y-2" aria-label="Retrieved source citations">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-[10px] font-semibold uppercase tracking-wide text-cyan-300">Sources reviewed first</h3>
        <span className="text-[10px] text-gray-600">{citations.length} citation{citations.length === 1 ? '' : 's'}</span>
      </div>
      {!citations.length && (
        <p role="alert" className="rounded border border-amber-900/70 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100">
          No source excerpts were returned. Treat this response as ungrounded; Navigator application is disabled.
        </p>
      )}
      {citations.map((citation, index) => (
        <article key={`${citation.sourceRef}-${index}`} className="rounded border border-gray-800 bg-gray-950/60 p-3 text-xs leading-5 text-gray-400">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div className="min-w-0">
              <p className="font-semibold text-gray-200">{citation.title || citation.sourceRef}</p>
              <p className="mt-0.5 font-mono text-[10px] text-gray-600">{citation.sourceType} · {citation.sourceRef}</p>
            </div>
            <div className="flex shrink-0 flex-wrap gap-1 text-[10px]">
              {citation.tlp && <span className="rounded border border-gray-700 px-1.5 py-0.5 text-gray-400">{citation.tlp}</span>}
              {citation.legalSensitive && <span className="rounded border border-amber-800 px-1.5 py-0.5 text-amber-300">legal-sensitive</span>}
              {citation.score != null && <span className="rounded border border-gray-700 px-1.5 py-0.5 text-gray-400">rank {formatScore(citation.score)}</span>}
              <span className={`rounded border px-1.5 py-0.5 ${citation.verified ? 'border-emerald-900 text-emerald-300' : 'border-amber-900 text-amber-300'}`}>
                {citation.verified ? 'verified source' : 'verify manually'}
              </span>
            </div>
          </div>
          <blockquote className="mt-2 whitespace-pre-wrap border-l-2 border-cyan-900 pl-3 text-gray-300">
            {citation.excerpt || 'No exact excerpt returned.'}
          </blockquote>
          <SafeEntityLink route={citation.route} label="Open authoritative record →" />
        </article>
      ))}
    </section>
  );
}

function EntityList({ entities }: { entities: RAGEntity[] }) {
  if (!entities.length) return null;
  return (
    <section className="space-y-2" aria-label="Retrieved intelligence entities">
      <h3 className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">Matched entities</h3>
      <div className="grid gap-2 md:grid-cols-2">
        {entities.map((entity, index) => (
          <article key={`${entity.sourceType}-${entity.sourceId}-${index}`} className="rounded border border-gray-800 bg-gray-950/60 p-3">
            <p className="text-sm font-semibold text-gray-200">{entity.title || entity.sourceId}</p>
            <p className="mt-1 font-mono text-[10px] text-gray-600">{entity.sourceType} · {entity.sourceId}</p>
            <MetadataPreview metadata={entity.metadata} />
            <SafeEntityLink route={entity.route} label="Open record →" />
          </article>
        ))}
      </div>
    </section>
  );
}

function ProposalReview({
  proposal,
  proposalIds,
  citationCount,
  citationsVerified,
  proposalDomainMismatch,
  proposalVersionMismatch,
  proposalExpired,
  invalidTechniqueIds,
  blocked,
  previewed,
  applied,
  confirmationOpen,
  applyMode,
  diff,
  evidenceReviewed,
  confirming,
  onPreview,
  onBeginConfirmation,
  onApplyModeChange,
  onEvidenceReviewedChange,
  onCancelConfirmation,
  onConfirm,
}: {
  proposal: NavigatorProposal;
  proposalIds: string[];
  citationCount: number;
  citationsVerified: boolean;
  proposalDomainMismatch: boolean;
  proposalVersionMismatch: boolean;
  proposalExpired: boolean;
  invalidTechniqueIds: string[];
  blocked: boolean;
  previewed: boolean;
  applied: boolean;
  confirmationOpen: boolean;
  applyMode: ApplyMode;
  diff: SelectionDiff;
  evidenceReviewed: boolean;
  confirming: boolean;
  onPreview: () => void;
  onBeginConfirmation: () => void;
  onApplyModeChange: (mode: ApplyMode) => void;
  onEvidenceReviewedChange: (reviewed: boolean) => void;
  onCancelConfirmation: () => void;
  onConfirm: () => void;
}) {
  return (
    <section className="rounded border border-cyan-900/70 bg-cyan-950/10 p-4" aria-label="Navigator proposal review">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wide text-cyan-300">Suggested Navigator layer · human review required</p>
          <h3 className="mt-1 text-sm font-semibold text-white">{proposal.name || 'RAG technique proposal'}</h3>
          <p className="mt-1 font-mono text-[10px] text-gray-600">
            {proposal.domain || 'unknown domain'} · ATT&amp;CK {proposal.attackVersion || 'server current'} · proposal {proposal.id.slice(0, 12)}
          </p>
        </div>
        {proposal.expiresAt && <span className="text-[10px] text-gray-600">expires {formatDate(proposal.expiresAt)}</span>}
      </div>
      {proposal.rationale && <p className="mt-3 whitespace-pre-wrap text-xs leading-5 text-gray-300">{proposal.rationale}</p>}

      <div className="mt-3 flex flex-wrap gap-1.5">
        {proposalIds.map(id => (
          <span key={id} className="rounded border border-gray-700 bg-gray-950 px-2 py-1 font-mono text-[10px] text-gray-300">{id}</span>
        ))}
      </div>

      {proposalDomainMismatch && <ValidationAlert>Proposal domain does not match the active Navigator domain.</ValidationAlert>}
      {proposalVersionMismatch && <ValidationAlert>Proposal catalog version does not match the active Navigator version.</ValidationAlert>}
      {proposalExpired && <ValidationAlert>This proposal expired or has no valid expiration. Generate a new grounded response.</ValidationAlert>}
      {(!proposal.id || !isUuid(proposal.id)) && <ValidationAlert>The proposal has no valid server identifier and cannot be confirmed.</ValidationAlert>}
      {(!proposal.checksum || !isChecksum(proposal.checksum)) && <ValidationAlert>The proposal has no valid integrity checksum and cannot be confirmed.</ValidationAlert>}
      {!proposal.attackVersion && <ValidationAlert>The proposal has no ATT&amp;CK catalog version and cannot be confirmed.</ValidationAlert>}
      {invalidTechniqueIds.length > 0 && <ValidationAlert>Unrecognized technique identifier format: {invalidTechniqueIds.join(', ')}</ValidationAlert>}
      {!proposalIds.length && <ValidationAlert>The proposal contains no techniques.</ValidationAlert>}
      {!citationCount && <ValidationAlert>The proposal has no cited evidence and cannot be applied.</ValidationAlert>}
      {citationCount > 0 && !citationsVerified && <ValidationAlert>One or more citations were not server-verified. The proposal cannot be applied.</ValidationAlert>}
      {citationCount > 0 && !proposal.requiresConfirmation && (
        <p className="mt-3 text-[10px] leading-4 text-amber-300">The server did not request confirmation, but this client still enforces source review and explicit confirmation.</p>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        <button type="button" className="secondary-action" disabled={blocked || applied} onClick={onPreview}>
          {previewed ? 'Preview active' : `Preview ${proposalIds.length} on Navigator`}
        </button>
        <button
          type="button"
          className="primary-action disabled:cursor-not-allowed disabled:opacity-40"
          disabled={blocked || !citationCount || applied}
          onClick={onBeginConfirmation}
        >
          {applied ? 'Proposal applied' : 'Review Add / Replace diff'}
        </button>
      </div>

      {confirmationOpen && !applied && (
        <div className="mt-4 space-y-4 rounded border border-amber-800/70 bg-amber-950/15 p-4" role="group" aria-label="Confirm Navigator proposal">
          <div>
            <h4 className="text-sm font-semibold text-amber-100">Confirm selection change</h4>
            <p className="mt-1 text-xs leading-5 text-amber-100/70">The server will revalidate this proposal before the local Navigator selection changes. This does not save a named layer.</p>
          </div>
          <fieldset>
            <legend className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">Application mode</legend>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              <ModeChoice
                mode="add"
                selected={applyMode === 'add'}
                title="Add to current selection"
                description="Preserves techniques already selected."
                onChange={onApplyModeChange}
              />
              <ModeChoice
                mode="replace"
                selected={applyMode === 'replace'}
                title="Replace current selection"
                description="Removes selected techniques absent from this proposal."
                onChange={onApplyModeChange}
              />
            </div>
          </fieldset>

          <SelectionDiffView diff={diff} mode={applyMode} />

          <label className="flex items-start gap-2 rounded border border-gray-800 bg-gray-950/50 p-3 text-xs leading-5 text-gray-300">
            <input
              type="checkbox"
              className="mt-1"
              checked={evidenceReviewed}
              disabled={confirming}
              onChange={event => onEvidenceReviewedChange(event.target.checked)}
            />
            <span>I reviewed the {citationCount} cited source{citationCount === 1 ? '' : 's'}, proposal rationale, domain/version, and the selection diff.</span>
          </label>

          <div className="flex justify-end gap-2">
            <button type="button" className="secondary-action" disabled={confirming} onClick={onCancelConfirmation}>Cancel</button>
            <button
              type="button"
              className="primary-action disabled:cursor-not-allowed disabled:opacity-40"
              disabled={!evidenceReviewed || confirming}
              onClick={onConfirm}
            >
              {confirming ? 'Revalidating proposal…' : applyMode === 'add' ? `Confirm and add ${proposalIds.length}` : `Confirm and replace with ${proposalIds.length}`}
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

function ModeChoice({
  mode,
  selected,
  title,
  description,
  onChange,
}: {
  mode: ApplyMode;
  selected: boolean;
  title: string;
  description: string;
  onChange: (mode: ApplyMode) => void;
}) {
  return (
    <label className={`flex cursor-pointer items-start gap-2 rounded border p-3 ${selected ? 'border-cyan-700 bg-cyan-950/20' : 'border-gray-800 bg-gray-950/40'}`}>
      <input type="radio" name="rag-apply-mode" checked={selected} onChange={() => onChange(mode)} />
      <span>
        <b className="block text-xs text-gray-200">{title}</b>
        <span className="mt-1 block text-[10px] leading-4 text-gray-500">{description}</span>
      </span>
    </label>
  );
}

interface SelectionDiff {
  added: string[];
  alreadySelected: string[];
  removed: string[];
  finalCount: number;
}

function SelectionDiffView({ diff, mode }: { diff: SelectionDiff; mode: ApplyMode }) {
  return (
    <section aria-label="Navigator selection diff">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <DiffMetric label="Added" value={diff.added.length} tone="emerald" />
        <DiffMetric label="Already selected" value={diff.alreadySelected.length} />
        <DiffMetric label="Removed" value={mode === 'replace' ? diff.removed.length : 0} tone={mode === 'replace' ? 'amber' : 'default'} />
        <DiffMetric label="Final selection" value={diff.finalCount} />
      </div>
      {(diff.added.length > 0 || (mode === 'replace' && diff.removed.length > 0)) && (
        <details className="mt-2 rounded border border-gray-800 bg-gray-950/40">
          <summary className="cursor-pointer px-3 py-2 text-xs text-gray-400">Review exact technique changes</summary>
          <div className="grid gap-3 border-t border-gray-800 p-3 sm:grid-cols-2">
            <TechniqueList title="Add" ids={diff.added} tone="text-emerald-300" />
            {mode === 'replace' && <TechniqueList title="Remove" ids={diff.removed} tone="text-amber-300" />}
          </div>
        </details>
      )}
    </section>
  );
}

function DiffMetric({
  label,
  value,
  tone = 'default',
}: {
  label: string;
  value: number;
  tone?: 'default' | 'emerald' | 'amber';
}) {
  const valueClass = tone === 'emerald'
    ? 'text-emerald-300'
    : tone === 'amber'
      ? 'text-amber-300'
      : 'text-gray-200';
  return (
    <div className="rounded border border-gray-800 bg-gray-950/50 p-2 text-center">
      <b className={`block text-sm ${valueClass}`}>{value}</b>
      <span className="text-[10px] text-gray-600">{label}</span>
    </div>
  );
}

function TechniqueList({ title, ids, tone }: { title: string; ids: string[]; tone: string }) {
  return (
    <div>
      <b className={`text-[10px] uppercase tracking-wide ${tone}`}>{title} ({ids.length})</b>
      <p className="mt-1 break-words font-mono text-[10px] leading-5 text-gray-500">{ids.length ? ids.join(', ') : 'None'}</p>
    </div>
  );
}

function MetadataPreview({ metadata }: { metadata: Record<string, unknown> }) {
  const entries = Object.entries(metadata)
    .filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value))
    .slice(0, 4);
  if (!entries.length) return null;
  return (
    <dl className="mt-2 space-y-1">
      {entries.map(([key, value]) => (
        <div key={key} className="grid grid-cols-[90px_minmax(0,1fr)] gap-2 text-[10px]">
          <dt className="truncate font-mono text-gray-700">{key}</dt>
          <dd className="truncate text-gray-500">{String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function SafeEntityLink({ route, label }: { route: string; label: string }) {
  if (!isSafeInternalRoute(route)) return null;
  return <Link to={route} className="mt-2 inline-flex text-[10px] text-cyan-300 hover:text-cyan-100">{label}</Link>;
}

function ValidationAlert({ children }: { children: ReactNode }) {
  return <p role="alert" className="mt-3 rounded border border-red-900/70 bg-red-950/20 p-2 text-xs text-red-200">{children}</p>;
}

function buildSelectionDiff(
  selectedTechniques: Set<string>,
  proposalTechniqueIds: string[],
  mode: ApplyMode,
): SelectionDiff {
  const selected = new Set([...selectedTechniques].map(normalizeTechniqueId));
  const proposal = new Set(proposalTechniqueIds.map(normalizeTechniqueId));
  const added = [...proposal].filter(id => !selected.has(id)).sort();
  const alreadySelected = [...proposal].filter(id => selected.has(id)).sort();
  const removed = mode === 'replace'
    ? [...selected].filter(id => !proposal.has(id)).sort()
    : [];
  return {
    added,
    alreadySelected,
    removed,
    finalCount: mode === 'replace' ? proposal.size : new Set([...selected, ...proposal]).size,
  };
}

function normalizeStatus(value: unknown): RAGStatus {
  const source = asRecord(value);
  const index = asRecord(source.index);
  const configuredLimit = optionalNumber(source.default_result_limit) ?? 12;
  const rawProviders = Array.isArray(source.providers)
    ? source.providers
    : Array.isArray(source.provider_catalog)
      ? source.provider_catalog
      : [];
  const providers = rawProviders
    .map(item => normalizeProvider(item))
    .filter((provider): provider is ProviderStatus => Boolean(provider));
  return {
    ready: optionalBoolean(source.ready ?? source.index_ready ?? index.ready ?? source.enabled),
    indexStatus: stringValue(
      source.index_status
      ?? source.last_run_status
      ?? asRecord(source.latest_run).status
      ?? index.status,
    ),
    documentCount: optionalNumber(
      source.document_count
      ?? source.documents_active
      ?? source.documents
      ?? index.document_count,
    ),
    chunkCount: optionalNumber(source.chunk_count ?? source.chunks ?? index.chunk_count),
    retrievalMode: stringValue(source.retrieval_mode ?? index.retrieval_mode),
    defaultResultLimit: Math.max(1, Math.min(25, Math.trunc(configuredLimit))),
    warnings: stringArray(source.warnings),
    providers,
  };
}

function normalizeProvider(value: unknown): ProviderStatus | null {
  const source = asRecord(value);
  const id = stringValue(source.id ?? source.provider);
  if (!id) return null;
  return {
    id,
    label: stringValue(source.label) || id,
    model: stringValue(source.model),
    configured: source.configured !== false,
    available: source.available !== false && source.configured !== false,
    status: stringValue(source.status) || (source.configured === false ? 'missing_configuration' : 'ready'),
    reason: stringValue(source.reason),
    remote: source.remote === true,
    isDefault: source.default === true || source.is_default === true,
  };
}

function providerStatusLabel(status: string) {
  return ({
    ready: 'ready',
    disabled_by_policy: 'disabled by policy',
    missing_credential: 'not configured',
    missing_configuration: 'not configured',
    invalid_endpoint: 'invalid endpoint',
    runtime_check_required: 'readiness check required',
    unreachable: 'endpoint unreachable',
    model_missing: 'model not installed',
    auth_error: 'authentication failed',
    endpoint_error: 'endpoint error',
    invalid_response: 'invalid endpoint response',
  } as Record<string, string>)[status] ?? 'unavailable';
}

function normalizeResult(value: unknown): RAGResult {
  const source = asRecord(value);
  const searchItems = arrayValue(source.items);
  const citations = (
    Array.isArray(source.citations) ? source.citations : searchItems
  ).map(normalizeCitation);
  const entities = (
    Array.isArray(source.entities) ? source.entities : searchItems
  ).map(normalizeEntity);
  const rawProposal = source.navigator_proposal;
  const proposal = rawProposal && typeof rawProposal === 'object'
    ? normalizeProposal(rawProposal)
    : null;
  const result: RAGResult = {
    assistanceId: stringValue(source.assistance_id),
    answer: stringValue(source.answer),
    retrievalMode: stringValue(source.retrieval_mode),
    effectiveTlp: stringValue(source.effective_tlp),
    citations,
    entities,
    warnings: uniqueStrings([
      ...stringArray(source.warnings),
      ...stringArray(source.cautions).map(caution => `Caution: ${caution}`),
    ]),
    proposal,
  };
  if (!result.answer && !result.citations.length && !result.entities.length && !result.proposal) {
    throw new Error('The RAG service returned no reviewable evidence or result.');
  }
  return result;
}

function normalizeCitation(value: unknown): RAGCitation {
  const source = asRecord(value);
  return {
    sourceRef: stringValue(source.source_ref ?? source.source_id),
    sourceType: stringValue(source.source_type),
    title: stringValue(source.title),
    excerpt: stringValue(source.excerpt),
    route: stringValue(source.route),
    tlp: stringValue(source.tlp),
    legalSensitive: source.legal_sensitive === true,
    score: optionalNumber(source.score),
    verified: source.verified === true,
  };
}

function normalizeEntity(value: unknown): RAGEntity {
  const source = asRecord(value);
  return {
    sourceType: stringValue(source.source_type),
    sourceId: stringValue(source.source_id),
    title: stringValue(source.title),
    route: stringValue(source.route),
    metadata: asRecord(source.metadata),
  };
}

function normalizeProposal(value: unknown): NavigatorProposal {
  const source = asRecord(value);
  return {
    id: stringValue(source.id),
    name: stringValue(source.name),
    domain: stringValue(source.domain),
    attackVersion: stringValue(source.attack_version),
    techniqueIds: uniqueStrings(source.technique_ids).map(normalizeTechniqueId),
    rationale: stringValue(source.rationale),
    checksum: stringValue(source.proposal_checksum),
    expiresAt: stringValue(source.expires_at),
    requiresConfirmation: source.requires_confirmation !== false,
  };
}

function normalizeTechniqueId(value: string) {
  return value.trim().toUpperCase();
}

function isTechniqueId(value: string) {
  return /^(?:T\d{4}(?:\.\d{3})?|AML\.[A-Z0-9][A-Z0-9._:-]*)$/.test(value);
}

function isUuid(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isChecksum(value: string) {
  return /^[0-9a-f]{64}$/.test(value);
}

function normalizeDomain(value: string) {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'enterprise' || normalized === 'enterprise-attack') return 'enterprise-attack';
  if (normalized === 'mobile' || normalized === 'mobile-attack') return 'mobile-attack';
  if (normalized === 'ics' || normalized === 'ics-attack') return 'ics-attack';
  return normalized;
}

function isSafeInternalRoute(value: string) {
  return value.length <= 1_000
    && value.startsWith('/')
    && !value.startsWith('//')
    && !value.includes('\\')
    && !/[\u0000-\u001f]/.test(value);
}

function isExpired(value: string) {
  const timestamp = new Date(value).getTime();
  return !Number.isFinite(timestamp) || timestamp <= Date.now();
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'unknown time' : date.toLocaleString();
}

function formatScore(value: number) {
  return Number.isFinite(value) ? value.toFixed(4) : 'n/a';
}

function splitProfileTerms(value: string) {
  return Array.from(new Set(
    value
      .split(/[,;\n]/)
      .map(item => item.trim().slice(0, 200))
      .filter(Boolean),
  )).slice(0, 100);
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : error ? String(error) : 'Unknown request failure.';
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function stringArray(value: unknown): string[] {
  return uniqueStrings(value);
}

function uniqueStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is string => typeof item === 'string').map(item => item.trim()).filter(Boolean))];
}

function optionalBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function sameStringSet(left: string[], right: string[]) {
  const normalizedLeft = [...new Set(left.map(normalizeTechniqueId))].sort();
  const normalizedRight = [...new Set(right.map(normalizeTechniqueId))].sort();
  return normalizedLeft.length === normalizedRight.length
    && normalizedLeft.every((value, index) => value === normalizedRight[index]);
}
