import { useDeferredValue, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';

import { queryLibraryApi, threatHuntingApi, type HuntQueryLibraryItem, type IOCQueryBuildResult } from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { HuntDashboard, type HuntFilters } from '@/components/ThreatHunting/HuntDashboard';
import { HuntWorkspace } from '@/components/ThreatHunting/HuntWorkspace';
import type { HuntAIAssistantMode } from '@/components/ThreatHunting/HuntAIAssistant';
import { hasRole, useCurrentUser } from '@/hooks/useCurrentUser';
import { useAppStore } from '@/store';

const EMPTY_FILTERS: HuntFilters = { q: '', status: '', priority: '', technique: '' };

export function ThreatHunting() {
  const navigate = useNavigate();
  const location = useLocation();
  const { huntId = '' } = useParams();
  const [searchParams] = useSearchParams();
  const [filters, setFilters] = useState<HuntFilters>(EMPTY_FILTERS);
  const deferredSearch = useDeferredValue(filters.q.trim());
  const deferredTechnique = useDeferredValue(filters.technique.trim().toUpperCase());
  const isNew = location.pathname.endsWith('/new');
  const isWorkspace = isNew || Boolean(huntId);
  const techniqueFilterValid = !deferredTechnique || /^T\d{4}(?:\.\d{3})?$/.test(deferredTechnique);
  const { selectedTechniques } = useAppStore();
  const currentUser = useCurrentUser();
  const canReadHunts = hasRole(currentUser.data, 'analyst');
  const requestedAssistant = searchParams.get('assistant') || '';
  const initialAssistantMode: HuntAIAssistantMode | '' = ['hypothesis', 'plan', 'query', 'findings', 'outcome'].includes(requestedAssistant)
    ? requestedAssistant as HuntAIAssistantMode
    : '';

  const templates = useQuery({
    queryKey: ['threat-hunting-templates'],
    queryFn: threatHuntingApi.templates,
    staleTime: 30 * 60 * 1000,
    enabled: canReadHunts,
  });
  const stats = useQuery({
    queryKey: ['threat-hunting-stats'],
    queryFn: threatHuntingApi.stats,
    enabled: canReadHunts && !isWorkspace,
  });
  const hunts = useQuery({
    queryKey: ['threat-hunting-hunts', deferredSearch, filters.status, filters.priority, deferredTechnique],
    queryFn: () => threatHuntingApi.hunts({
      q: deferredSearch || undefined,
      status: filters.status || undefined,
      priority: filters.priority || undefined,
      technique_id: deferredTechnique || undefined,
    }),
    enabled: canReadHunts && !isWorkspace && techniqueFilterValid,
  });
  const detail = useQuery({
    queryKey: ['threat-hunting-hunt', huntId],
    queryFn: () => threatHuntingApi.get(huntId),
    enabled: canReadHunts && Boolean(huntId),
  });
  const libraryId = searchParams.get('library') || '';
  const libraryItem = useQuery({
    queryKey: ['query-library-item', libraryId],
    queryFn: () => queryLibraryApi.get(libraryId),
    enabled: canReadHunts && isNew && Boolean(libraryId),
  });
  const sessionDraft = useMemo(() => {
    if (!isNew || searchParams.get('library_draft') !== 'session') return null;
    try {
      return JSON.parse(sessionStorage.getItem('adversarygraph:query-library-draft') || 'null') as IOCQueryBuildResult | null;
    } catch {
      return null;
    }
  }, [isNew, searchParams]);

  const initialTechniques = useMemo(() => {
    const requested = searchParams.get('technique') || searchParams.get('technique_id') || '';
    const values = requested
      ? requested.split(',').map(value => value.trim().toUpperCase()).filter(Boolean)
      : Array.from(selectedTechniques).map(value => value.toUpperCase());
    return Array.from(new Set(values));
  }, [searchParams, selectedTechniques]);

  if (!canReadHunts) {
    return (
      <div className="flex min-h-full flex-col">
        <Header title="Threat Hunting" />
        <main className="flex flex-1 items-center justify-center px-6 py-10">
          <div role="status" className="rounded border border-gray-800 bg-gray-950/60 px-6 py-5 text-sm text-gray-400">
            {currentUser.isError ? 'Unable to verify analyst access.' : 'Verifying analyst access…'}
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="flex min-h-full flex-col">
      <Header title="Threat Hunting" />
      {isWorkspace ? (
        <HuntWorkspace
          hunt={detail.data ?? null}
          templates={templates.data ?? []}
          initialTemplateId={searchParams.get('template') || ''}
          initialTechniques={initialTechniques}
          initialSourceType={searchParams.get('source') || ''}
          initialSourceRef={searchParams.get('source_ref') || ''}
          initialSourceSessionId={searchParams.get('source_session_id') || ''}
          initialAssistantMode={initialAssistantMode}
          initialLibraryItem={(libraryItem.data ?? sessionDraft) as HuntQueryLibraryItem | IOCQueryBuildResult | null}
          defaultOwner={currentUser.data?.name ?? ''}
          loading={Boolean(huntId) && detail.isLoading}
          loadError={errorMessage(detail.error)}
          onBack={() => navigate('/threat-hunting')}
          onCreated={id => navigate(`/threat-hunting/${id}`, { replace: true })}
        />
      ) : (
        <HuntDashboard
          stats={stats.data}
          hunts={hunts.data ?? []}
          templates={templates.data ?? []}
          filters={filters}
          onFiltersChange={setFilters}
          onOpenHunt={id => navigate(`/threat-hunting/${id}`)}
          onCreate={() => navigate('/threat-hunting/new')}
          onUseTemplate={template => navigate(`/threat-hunting/new?template=${encodeURIComponent(template)}`)}
          loading={stats.isLoading || hunts.isLoading || templates.isLoading}
          error={errorMessage(stats.error || hunts.error || templates.error)}
        />
      )}
    </div>
  );
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : error ? String(error) : '';
}
