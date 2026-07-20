import type { Page } from '@playwright/test';

const technique = {
  attack_id: 'T1595',
  name: 'Active Scanning',
  description: 'Probe public targets before an attack.',
  platforms: ['Linux', 'Windows', 'Network'],
  tactics: ['reconnaissance'],
  is_subtechnique: false,
  parent_attack_id: null,
};

const huntTransitions: Record<string, string[]> = {
  queued: ['planned', 'running', 'cancelled', 'archived'],
  draft: ['planned', 'cancelled', 'archived'],
  planned: ['running', 'cancelled', 'archived'],
  running: ['review', 'cancelled', 'archived'],
  review: ['running', 'completed', 'cancelled', 'archived'],
  completed: ['archived'],
  cancelled: ['archived'],
  archived: [],
};

const mutableHuntStatuses = ['queued', 'draft', 'planned', 'running', 'review'];
const readyHuntStatuses = ['planned', 'running', 'review', 'completed'];
const completionDispositions = ['no_matches', 'benign', 'benign_policy_relevant', 'suspicious', 'confirmed_malicious', 'inconclusive', 'telemetry_gap', 'query_failure'];
const tlpRank: Record<string, number> = {
  'TLP:CLEAR': 0,
  'TLP:GREEN': 1,
  'TLP:AMBER': 2,
  'TLP:AMBER+STRICT': 3,
  'TLP:RED': 4,
};

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function readinessError(record: Record<string, unknown>) {
  const status = String(record.status ?? '');
  if (!readyHuntStatuses.includes(status)) return '';
  const missing = [
    !String(record.scope ?? '').trim() && 'scope',
    stringList(record.telemetry_sources).length === 0 && 'telemetry_sources',
    !String(record.expected_evidence ?? '').trim() && 'expected_evidence',
    !String(record.false_positive_notes ?? '').trim() && 'false_positive_notes',
  ].filter(Boolean);
  return missing.length ? `Hunt status ${status} requires: ${missing.join(', ')}` : '';
}

function invalidTechnique(values: unknown) {
  return stringList(values).find(value => !/^T\d{4}(?:\.\d{3})?$/.test(value.toUpperCase())) ?? '';
}

function isTlpDowngrade(current: unknown, proposed: unknown) {
  const currentRank = tlpRank[String(current)] ?? -1;
  const proposedRank = tlpRank[String(proposed)] ?? -1;
  return proposedRank < currentRank;
}

export async function mockApi(page: Page) {
  const huntTemplate = {
    id: 'powershell-encoded-execution',
    title: 'Suspicious encoded PowerShell execution',
    hypothesis: 'An adversary is using encoded or obfuscated PowerShell on managed endpoints.',
    description: 'Review process and script-block activity and preserve the analyst decision.',
    technique_ids: ['T1059.001', 'T1027'],
    tactics: ['execution', 'stealth', 'defense-impairment'],
    telemetry_sources: ['Process creation', 'PowerShell Script Block Logging'],
    required_fields: ['@timestamp', 'host.name', 'process.command_line'],
    query_language: 'kql',
    query_text: 'process.name : "powershell.exe" and process.command_line : ("-enc" or "FromBase64String")',
    query_note: 'Implementation-independent example only. Validate syntax, fields, scope, and cost in the approved telemetry backend.',
    expected_evidence: 'Encoded commands, suspicious ancestry, or correlated network and file activity.',
    false_positive_notes: 'Approved automation and deployment tooling can use encoded PowerShell.',
    tags: ['endpoint', 'powershell'],
  };
  const baseHunt = {
    title: huntTemplate.title,
    hypothesis: huntTemplate.hypothesis,
    description: huntTemplate.description,
    scope: 'Managed Windows endpoints in the finance segment during the last seven days.',
    status: 'review',
    priority: 'P1 High',
    owner: 'Detection Engineering',
    tlp: 'TLP:AMBER',
    source_type: 'threat-radar',
    source_ref: 'case:tr-2026-0042',
    case_id: 'tr-2026-0042',
    technique_ids: huntTemplate.technique_ids,
    tactics: huntTemplate.tactics,
    telemetry_sources: huntTemplate.telemetry_sources,
    required_fields: huntTemplate.required_fields,
    tags: huntTemplate.tags,
    query_language: huntTemplate.query_language,
    query_text: huntTemplate.query_text,
    time_range_start: '2026-07-10T00:00:00Z',
    time_range_end: '2026-07-17T00:00:00Z',
    expected_evidence: huntTemplate.expected_evidence,
    false_positive_notes: huntTemplate.false_positive_notes,
    assumptions: 'Script Block Logging is enabled and clocks are synchronized.',
    result_summary: '',
    disposition: 'undetermined',
    created_by: 'analyst@example.test',
    created_at: '2026-07-16T08:00:00Z',
    updated_at: '2026-07-17T08:00:00Z',
    completed_at: null,
    archived_at: null,
  };
  let hunts = [{ id: 'hunt-1', ...baseHunt }];
  let findings = [{
    id: 'finding-1',
    hunt_id: 'hunt-1',
    title: 'Encoded PowerShell spawned by spreadsheet process',
    summary: 'An office process launched encoded PowerShell on one workstation; the event requires incident review.',
    severity: 'high',
    confidence: 86,
    status: 'reviewed',
    verdict: 'supports',
    tlp: 'TLP:AMBER',
    evidence_type: 'SIEM event',
    evidence_ref: 'siem:event:12345',
    event_time: '2026-07-16T12:30:00Z',
    observables: ['host-01', '10.0.0.5'],
    technique_ids: ['T1059.001'],
    analyst: 'analyst@example.test',
    query_version_id: 'query-version-1',
    notes: 'Parent process is unusual for the user baseline.',
    created_at: '2026-07-17T08:15:00Z',
    updated_at: '2026-07-17T08:30:00Z',
    archived_at: null,
  }];
  let queryVersions = [{
    id: 'query-version-1',
    hunt_id: 'hunt-1',
    version: 1,
    language: 'kql',
    query_text: huntTemplate.query_text,
    backend_assumptions: 'Validate destination field mappings.',
    checksum: '64b9d5f2f4c17b671e6877412d62ef72056d9df61601b1303f5bd3c0c79f9688',
    created_by: 'analyst@example.test',
    created_at: '2026-07-17T08:00:00Z',
  }];
  const reportSessionId = '11111111-1111-4111-8111-111111111111';
  let storedReportTlp = 'TLP:AMBER+STRICT';
  const reportCollectionItem = {
    session_id: reportSessionId,
    title: 'Identity provider intrusion research',
    source_url: 'https://example.test/research/identity-intrusion',
    publisher: 'Example Research',
    status: 'completed',
    provider: 'local',
    model: 'llama3.1:8b',
    domain: 'enterprise-attack',
    tlp: storedReportTlp,
    created_at: '2026-07-16T07:00:00Z',
    updated_at: '2026-07-16T07:30:00Z',
    summary: 'The report documents suspicious identity federation changes followed by mailbox access.',
    source_text_available: true,
    counts: { reports: 1, ttps: 2, iocs: 0, cves: 0, threat_actors: 1, sectors: 1, infrastructure: 0 },
    tags: {},
  };
  const ineligibleReportItem = {
    ...reportCollectionItem,
    session_id: '22222222-2222-4222-8222-222222222222',
    title: 'Unparsed ATLAS research note',
    status: 'stored',
    domain: 'atlas',
    source_text_available: false,
  };
  const aiCitation = {
    source_session_id: reportSessionId,
    source_type: 'report',
    source_ref: reportSessionId,
    quote: 'The actor modified federation trust settings before accessing cloud mailboxes.',
    start: 124,
    end: 209,
    verified: true,
  };

  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api/, '');
    const json = (body: unknown) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    const apiError = (status: number, detail: string) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify({ detail }) });

    if (path === '/auth/status') {
      return json({
        auth_enabled: false,
        native_login_enabled: false,
        user_count: 1,
        bootstrap_configured: false,
        bootstrap_required: false,
        roles: ['viewer', 'analyst', 'admin'],
        permissions: ['read', 'run_attack_simulation', 'forward_siem'],
        role_permissions: {},
      });
    }
    if (path === '/auth/me') {
      return json({ auth_enabled: false, name: 'Local Analyst', username: 'local', roles: ['admin'], role: 'admin', permissions: ['read', 'run_attack_simulation', 'forward_siem'] });
    }
    if (path === '/system/selftest') {
      return json({
        status: 'ok',
        duration_ms: 12,
        checks: [{ name: 'database', status: 'ok', message: 'Database connection succeeded.' }],
      });
    }
    if (path === '/sync/status') {
      return json({
        enabled_sources: 0,
        degraded_sources: 0,
        total_indicators: 0,
        sources: [],
        cve_sources: [],
        cve_total_records: 1,
        cve_known_exploited: 0,
      });
    }
    if (path === '/apt/groups') return json([]);
    if (path === '/attack/tactics') {
      return json([{ attack_id: 'TA0043', shortname: 'reconnaissance', name: 'Reconnaissance' }]);
    }
    if (path === '/attack/techniques') return json([technique]);
    if (path === '/ioc/sources') return json([]);
    if (path === '/simulation/catalog') {
      return json([{
        id: 'sim-t1595-http-fingerprint',
        technique_id: 'T1595',
        name: 'HTTP/TLS service fingerprint plan',
        description: 'Fingerprint a lab web endpoint and collect validation telemetry.',
        category: 'reconnaissance',
        target_types: ['web', 'http'],
        risk_level: 0,
        steps: ['Send safe probe requests.'],
        expected_telemetry: ['access log', 'event_id=AG-WEB-1595'],
      }]);
    }
    if (path === '/simulation/targets') {
      return json([{
        id: 'lab-web-01',
        name: 'Lab web server',
        address: 'http://attack-lab-web:8080',
        target_type: 'web',
        environment: 'lab',
        owner: 'AdversaryGraph',
        authorization: 'approved',
        allowed_simulations: ['sim-t1595-http-fingerprint'],
      }]);
    }
    if (path === '/simulation/ai-assistant/scenarios') {
      return json([{
        id: 'apt29-identity-chain',
        name: 'APT29-style identity chain',
        difficulty: 'advanced',
        description: 'Identity, PowerShell, and exfiltration telemetry story.',
        technique_ids: ['T1595', 'T1110.001', 'T1078'],
        preconditions: ['SIEM collector configured.'],
        success_criteria: ['Correlated detections appear.'],
        telemetry_sources: ['windows_security', 'sysmon'],
        expected_detections: ['Password spray followed by valid login.'],
        tags: ['identity', 'endpoint'],
      }]);
    }
    if (path === '/simulation/attack-flows') {
      return json([{
        id: 'flow-1',
        run_id: 'run-smoke-1',
        mode: 'challenge',
        ai_provider: 'local',
        ai_model: 'deterministic',
        ai_used: false,
        complicated_attack: true,
        actor_profile: 'apt29',
        scenario_id: 'apt29-identity-chain',
        scenario_name: 'APT29-style identity chain',
        summary: 'APT29-style identity chain',
        technique_ids: ['T1595', 'T1110.001', 'T1078'],
        event_count: 12,
        last_delivery_status: 200,
        last_delivery_ok: true,
        last_delivery_error: '',
        created_at: '2026-07-01T00:00:00Z',
        updated_at: '2026-07-01T00:00:00Z',
        attack_plan: { summary: 'APT29-style identity chain', kill_chain: [], validation_note: '' },
        events: [],
        delivery: {},
      }]);
    }
    if (path === '/simulation/siem-destinations') return json([]);
    if (path === '/cve/sources') return json([]);
    if (path === '/cve/library') {
      return json({
        total: 1,
        limit: 100,
        offset: 0,
        items: [{
          id: 1,
          cve_id: 'CVE-2026-0001',
          source: 'nvd',
          description: 'Example CVE used for UI smoke coverage.',
          published: '2026-07-01',
          last_modified: '2026-07-01',
          vuln_status: 'Analyzed',
          cvss: { version: '3.1', score: '9.8', severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
          cwe_ids: ['CWE-79'],
          cpe_matches: [],
          references: [],
          tags: [],
          known_exploited: false,
          kev_due_date: '',
          kev_required_action: '',
        }],
      });
    }
    if (path === '/analyze/sessions/collection') {
      return json({
        total: 2,
        limit: 150,
        offset: 0,
        items: [
          { ...reportCollectionItem, tlp: storedReportTlp },
          { ...ineligibleReportItem, tlp: storedReportTlp },
        ],
      });
    }
    if (path === `/analyze/sessions/${reportSessionId}/linked-report`) {
      if (route.request().method() === 'PATCH') {
        const body = route.request().postDataJSON();
        if (typeof body.tlp === 'string') storedReportTlp = body.tlp;
      }
      return json({
        session_id: reportSessionId,
        name: reportCollectionItem.title,
        provider: reportCollectionItem.provider,
        model: reportCollectionItem.model,
        domain: reportCollectionItem.domain,
        tlp: storedReportTlp,
        created_at: reportCollectionItem.created_at,
        source_text: 'The actor modified federation trust settings before accessing cloud mailboxes.',
        source_text_available: true,
        source_note: '',
        summary: reportCollectionItem.summary,
        techniques: [],
        apt_matches: [],
        entities: [],
        report_images: [],
        report_intake: { url: reportCollectionItem.source_url, publisher: reportCollectionItem.publisher },
      });
    }
    if (path === '/threat-hunting/ai/providers' && route.request().method() === 'GET') {
      return json([
        { id: 'local', label: 'Local', model: 'llama3.1:8b', configured: true, available: true, status: 'ready', reason: 'Configured local model is reachable.', remote: false, requires_acknowledgement: false, default: true },
        { id: 'claude', label: 'Anthropic Claude', model: 'claude-opus-4-8', configured: true, available: true, status: 'configured_and_permitted', reason: 'Credential is configured and operator policy permits selection. Connectivity and model access are checked when a request runs.', remote: true, requires_acknowledgement: true, default: false },
        { id: 'openai', label: 'OpenAI', model: 'gpt-4.1', configured: true, available: true, status: 'configured_and_permitted', reason: 'Credential is configured and operator policy permits selection. Connectivity and model access are checked when a request runs.', remote: true, requires_acknowledgement: true, default: false },
        { id: 'gemini', label: 'Google Gemini', model: 'gemini-3.5-flash', configured: true, available: true, status: 'configured_and_permitted', reason: 'Credential is configured and operator policy permits selection. Connectivity and model access are checked when a request runs.', remote: true, requires_acknowledgement: true, default: false },
        { id: 'minimax', label: 'MiniMax', model: 'MiniMax-M2.7', configured: true, available: true, status: 'configured_and_permitted', reason: 'Credential is configured and operator policy permits selection. Connectivity and model access are checked when a request runs.', remote: true, requires_acknowledgement: true, default: false },
      ]);
    }
    if (path === '/threat-hunting/ai/hypotheses' && route.request().method() === 'POST') {
      const body = route.request().postDataJSON();
      const remoteProvider = ['claude', 'openai', 'gemini', 'minimax'].includes(String(body.provider));
      const providerModels: Record<string, string> = {
        local: 'llama3.1:8b',
        claude: 'claude-opus-4-8',
        openai: 'gpt-4.1',
        gemini: 'gemini-3.5-flash',
        minimax: 'MiniMax-M2.7',
      };
      if (body.source_session_id !== reportSessionId) return apiError(404, 'Stored report or research session not found');
      if (remoteProvider && ['TLP:AMBER+STRICT', 'TLP:RED'].includes(body.tlp)) return apiError(403, `${body.tlp} context is local-only`);
      if (remoteProvider && !body.cloud_processing_acknowledged) return apiError(422, 'Remote AI processing requires explicit acknowledgment');
      return json({
        assistance_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        provider: body.provider,
        model: providerModels[String(body.provider)] ?? 'llama3.1:8b',
        lifecycle_status: 'suggested',
        generated_at: '2026-07-18T08:00:00Z',
        prompt_version: 'threat-hunt-hypothesis-v1',
        source_session_id: reportSessionId,
        source_type: 'report',
        source_title: reportCollectionItem.title,
        source_ref: reportSessionId,
        candidates: [{
          title: 'Suspicious federation trust modification',
          hypothesis: 'If an adversary modified identity federation trust, then audit telemetry should show an unusual trust update followed by mailbox access from a new session.',
          description: 'Derived from reviewed identity intrusion research.',
          scope: 'Identity provider audit logs and cloud mailbox sign-ins for the last fourteen days.',
          technique_ids: ['T1098', 'T1078'],
          tactics: ['persistence', 'defense-evasion'],
          telemetry_sources: ['Identity provider audit logs', 'Cloud mailbox sign-in logs'],
          required_fields: ['@timestamp', 'actor.id', 'operation.name', 'source.ip'],
          tags: ['identity', 'report-derived'],
          query_language: 'kql',
          query_text: 'operation.name : "Update federation trust"',
          expected_evidence: 'A federation trust update followed by mailbox access from a new session.',
          false_positive_notes: 'Approved identity migrations can produce the same administrative operation.',
          assumptions: 'Identity audit logs are complete for the scoped period.',
          rationale: 'The sequence is falsifiable and tied to two distinct telemetry sources.',
          source_evidence: [aiCitation],
        }],
        warnings: ['Validate tenant-specific field names before using the query.'],
        requires_human_review: true,
        execution_boundary: 'No telemetry query was executed and no hunt record was created.',
      });
    }
    if (path === '/threat-hunting/ai/assist' && route.request().method() === 'POST') {
      const body = route.request().postDataJSON();
      const stage = String(body.stage || '');
      const context = body.context || {};
      const remoteProvider = ['claude', 'openai', 'gemini', 'minimax'].includes(String(body.provider));
      const providerModels: Record<string, string> = {
        local: 'llama3.1:8b',
        claude: 'claude-opus-4-8',
        openai: 'gpt-4.1',
        gemini: 'gemini-3.5-flash',
        minimax: 'MiniMax-M2.7',
      };
      const validTlpMarkings = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'];
      if (!['plan', 'query', 'findings', 'outcome'].includes(stage)) return apiError(422, 'Unsupported AI assistance stage');
      if (!body.hunt_id && stage !== 'plan') return apiError(422, 'Save the hunt before requesting this stage');
      if (!body.hunt_id && stage === 'plan' && remoteProvider && !validTlpMarkings.includes(context.tlp)) {
        return apiError(422, 'Unsaved remote AI assistance requires an explicit valid TLP marking');
      }
      if (remoteProvider && ['TLP:AMBER+STRICT', 'TLP:RED'].includes(context.tlp)) return apiError(403, `${context.tlp} context is local-only`);
      if (remoteProvider && !body.cloud_processing_acknowledged) return apiError(422, 'Remote AI processing requires explicit acknowledgment');
      const stagePatch: Record<string, unknown> = {
        plan: {
          title: 'AI must not overwrite an existing hunt title',
          scope: 'Managed identity and endpoint telemetry for a bounded fourteen-day period.',
          technique_ids: ['T1078'],
          telemetry_sources: ['Identity provider audit logs'],
          assumptions: 'Clock synchronization and identity audit retention are verified.',
        },
        query: {
          query_language: 'kql',
          query_text: 'operation.name : "Update federation trust"',
          telemetry_sources: ['Identity provider audit logs'],
          required_fields: ['operation.name', 'actor.id', 'source.ip'],
        },
        findings: { technique_ids: ['T1078'], tags: ['ai-reviewed'] },
        outcome: {
          result_summary: 'The reviewed evidence supports a bounded identity investigation, with remaining gaps in historical sign-in retention.',
          disposition: 'confirmed_malicious',
          status: 'completed',
        },
      }[stage] as Record<string, unknown>;
      return json({
        assistance_id: `bbbbbbbb-bbbb-4bbb-8bbb-${stage.padEnd(12, '0').slice(0, 12)}`,
        provider: body.provider,
        model: providerModels[String(body.provider)] ?? 'llama3.1:8b',
        stage,
        lifecycle_status: 'suggested',
        generated_at: '2026-07-18T08:10:00Z',
        prompt_version: `threat-hunt-${stage}-v1`,
        summary: `AI suggestions for the ${stage} stage are ready for analyst review.`,
        recommended_actions: ['Verify the proposed fields against the source and local telemetry schema.'],
        questions: ['Which approved telemetry system will be used for validation?'],
        evidence_gaps: ['Historical coverage has not been independently verified.'],
        cautions: ['Do not treat this output as proof of execution or compromise.'],
        suggested_patch: stagePatch,
        finding_drafts: stage === 'findings' ? [{
          title: 'Federation trust update requires validation',
          summary: 'An identity administration event aligns with the hunt hypothesis but still requires source-event review.',
          severity: 'high',
          confidence: 72,
          status: 'reviewed',
          verdict: 'supports',
          tlp: 'TLP:CLEAR',
          evidence_type: 'Identity audit event',
          evidence_ref: 'identity:event:pending-review',
          event_time: null,
          observables: ['tenant.example'],
          technique_ids: ['T1098'],
          notes: 'AI-generated draft; verify the canonical event before saving.',
        }] : [],
        citations: [aiCitation],
        warnings: [],
        requires_human_review: true,
        execution_boundary: 'No telemetry query was executed and no hunt or finding record was changed.',
      });
    }
    if (path === '/threat-hunting/templates') return json([huntTemplate]);
    if (path === '/threat-hunting/stats') {
      const visibleFindings = findings.filter(item => !item.archived_at);
      return json({
        total_hunts: hunts.length,
        active_hunts: hunts.filter(item => ['queued', 'planned', 'running', 'review'].includes(item.status)).length,
        completed_hunts: hunts.filter(item => item.status === 'completed').length,
        total_findings: visibleFindings.length,
        high_priority_findings: visibleFindings.filter(item => ['high', 'critical'].includes(item.severity)).length,
        by_status: Object.fromEntries(['queued', 'draft', 'planned', 'running', 'review', 'completed', 'cancelled', 'archived'].map(status => [status, hunts.filter(item => item.status === status).length])),
        by_priority: {},
      });
    }
    if (path === '/threat-hunting/hunts' && route.request().method() === 'GET') {
      const q = (url.searchParams.get('q') || '').toLowerCase();
      const status = url.searchParams.get('status') || '';
      const priority = url.searchParams.get('priority') || '';
      const techniqueId = (url.searchParams.get('technique_id') || '').toUpperCase();
      return json(hunts.filter(item => (
        (!q || `${item.title} ${item.hypothesis}`.toLowerCase().includes(q))
        && (!status || item.status === status)
        && (!priority || item.priority === priority)
        && (!techniqueId || item.technique_ids.includes(techniqueId))
      )));
    }
    if (path === '/threat-hunting/hunts' && route.request().method() === 'POST') {
      const body = route.request().postDataJSON();
      if (String(body.title || '').trim().length < 3) return apiError(422, 'String should have at least 3 characters');
      if (String(body.hypothesis || '').trim().length < 10) return apiError(422, 'String should have at least 10 characters');
      if (invalidTechnique(body.technique_ids)) return apiError(422, 'Invalid ATT&CK technique IDs');
      if (!['draft', 'planned'].includes(String(body.status || 'draft'))) return apiError(422, 'New analyst-created hunts must start as draft or planned');
      const readyError = readinessError(body);
      if (readyError) return apiError(422, readyError);
      const created = {
        ...body,
        id: 'hunt-new',
        source_type: 'manual',
        source_ref: '',
        created_by: 'Local Analyst',
        created_at: '2026-07-17T09:00:00Z',
        updated_at: '2026-07-17T09:00:00Z',
        completed_at: null,
        archived_at: null,
        case_id: null,
      };
      hunts = [created, ...hunts];
      if (String(created.query_text || '')) {
        queryVersions = [{
          id: `query-version-${queryVersions.length + 1}`,
          hunt_id: created.id,
          version: 1,
          language: created.query_language,
          query_text: created.query_text,
          backend_assumptions: created.assumptions,
          checksum: 'a'.repeat(64),
          created_by: created.created_by,
          created_at: created.created_at,
        }, ...queryVersions];
      }
      return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(created) });
    }
    const huntMatch = path.match(/^\/threat-hunting\/hunts\/([^/]+)$/);
    if (huntMatch && route.request().method() === 'GET') {
      const hunt = hunts.find(item => item.id === huntMatch[1]);
      return hunt
        ? json({
          ...hunt,
          findings: findings.filter(item => item.hunt_id === hunt.id && !item.archived_at),
          query_versions: queryVersions.filter(item => item.hunt_id === hunt.id).sort((left, right) => right.version - left.version),
        })
        : apiError(404, 'Threat hunt not found');
    }
    if (huntMatch && route.request().method() === 'PATCH') {
      const body = route.request().postDataJSON();
      const index = hunts.findIndex(item => item.id === huntMatch[1]);
      if (index < 0) return apiError(404, 'Threat hunt not found');
      const current = hunts[index];
      if (!mutableHuntStatuses.includes(current.status)) return apiError(409, `Hunt is ${current.status} and its evidence record is read-only`);
      if (body.technique_ids && invalidTechnique(body.technique_ids)) return apiError(422, 'Invalid ATT&CK technique IDs');
      if (body.tlp && isTlpDowngrade(current.tlp, body.tlp)) return apiError(422, `TLP cannot be downgraded from ${current.tlp} to ${body.tlp}`);
      const proposedStatus = String(body.status || current.status);
      if (proposedStatus === 'archived') return apiError(409, 'Use the archive endpoint so archival provenance is recorded');
      if (proposedStatus !== current.status && !(huntTransitions[current.status] || []).includes(proposedStatus)) {
        return apiError(409, `Invalid hunt transition: ${current.status} -> ${proposedStatus}`);
      }
      const merged = { ...current, ...body, status: proposedStatus };
      const readyError = readinessError(merged);
      if (readyError) return apiError(422, readyError);
      const activeFindings = findings.filter(item => item.hunt_id === current.id && !item.archived_at);
      if (proposedStatus === 'completed') {
        if (!String(merged.result_summary || '').trim()) return apiError(422, 'A completed hunt requires a result summary');
        if (!completionDispositions.includes(String(merged.disposition || ''))) return apiError(422, 'A completed hunt requires a reviewed disposition');
        if (activeFindings.some(item => item.status === 'new')) return apiError(422, 'Review or archive all new findings before completing the hunt');
        if (
          ['suspicious', 'confirmed_malicious'].includes(String(merged.disposition))
          && !activeFindings.some(item => item.verdict === 'supports' && ['reviewed', 'escalated', 'closed'].includes(item.status))
        ) return apiError(422, 'Suspicious or malicious dispositions require a reviewed supporting finding');
      }
      const queryChanged = ['query_text', 'query_language', 'assumptions'].some(key => key in body && body[key] !== current[key as keyof typeof current]);
      const raisedTlp = body.tlp && (tlpRank[String(body.tlp)] ?? -1) > (tlpRank[current.tlp] ?? -1);
      hunts[index] = {
        ...merged,
        completed_at: proposedStatus === 'completed' ? current.completed_at || '2026-07-17T09:10:00Z' : current.completed_at,
        updated_at: '2026-07-17T09:10:00Z',
      };
      if (raisedTlp) {
        findings = findings.map(item => item.hunt_id === current.id && isTlpDowngrade(body.tlp, item.tlp)
          ? { ...item, tlp: body.tlp, updated_at: '2026-07-17T09:10:00Z' }
          : item);
      }
      if (queryChanged && String(merged.query_text || '')) {
        const latest = queryVersions.filter(item => item.hunt_id === current.id).reduce((value, item) => Math.max(value, item.version), 0);
        queryVersions = [{
          id: `query-version-${queryVersions.length + 1}`,
          hunt_id: current.id,
          version: latest + 1,
          language: String(merged.query_language),
          query_text: String(merged.query_text),
          backend_assumptions: String(merged.assumptions || ''),
          checksum: String(latest + 1).padEnd(64, 'b'),
          created_by: 'Local Analyst',
          created_at: '2026-07-17T09:10:00Z',
        }, ...queryVersions];
      }
      return json(hunts[index]);
    }
    const archiveMatch = path.match(/^\/threat-hunting\/hunts\/([^/]+)\/archive$/);
    if (archiveMatch && route.request().method() === 'POST') {
      const index = hunts.findIndex(item => item.id === archiveMatch[1]);
      if (index < 0) return apiError(404, 'Threat hunt not found');
      if (hunts[index].status !== 'archived' && !(huntTransitions[hunts[index].status] || []).includes('archived')) {
        return apiError(409, `Hunt cannot be archived from status ${hunts[index].status}`);
      }
      hunts[index] = { ...hunts[index], status: 'archived', archived_at: '2026-07-17T09:15:00Z', updated_at: '2026-07-17T09:15:00Z' };
      return json(hunts[index]);
    }
    const findingsMatch = path.match(/^\/threat-hunting\/hunts\/([^/]+)\/findings$/);
    if (findingsMatch && route.request().method() === 'GET') return json(findings.filter(item => item.hunt_id === findingsMatch[1] && !item.archived_at));
    if (findingsMatch && route.request().method() === 'POST') {
      const body = route.request().postDataJSON();
      const hunt = hunts.find(item => item.id === findingsMatch[1]);
      if (!hunt) return apiError(404, 'Threat hunt not found');
      if (!mutableHuntStatuses.includes(hunt.status)) return apiError(409, `Hunt is ${hunt.status} and its evidence record is read-only`);
      if (String(body.title || '').trim().length < 3) return apiError(422, 'String should have at least 3 characters');
      if (String(body.evidence_type || 'event').trim().length < 2) return apiError(422, 'String should have at least 2 characters');
      if (invalidTechnique(body.technique_ids)) return apiError(422, 'Invalid ATT&CK technique IDs');
      const findingTlp = body.tlp || hunt.tlp;
      if (isTlpDowngrade(hunt.tlp, findingTlp)) return apiError(422, `TLP cannot be downgraded from ${hunt.tlp} to ${findingTlp}`);
      const requestedVersion = body.query_version_id;
      if (requestedVersion && !queryVersions.some(item => item.id === requestedVersion && item.hunt_id === hunt.id)) return apiError(422, 'query_version_id does not belong to this hunt');
      const latestVersion = queryVersions.filter(item => item.hunt_id === hunt.id).sort((left, right) => right.version - left.version)[0];
      const finding = {
        ...body,
        id: `finding-${findings.length + 1}`,
        hunt_id: findingsMatch[1],
        analyst: 'Local Analyst',
        tlp: findingTlp,
        query_version_id: requestedVersion ?? latestVersion?.id ?? null,
        created_at: '2026-07-17T09:20:00Z',
        updated_at: '2026-07-17T09:20:00Z',
        archived_at: null,
      };
      findings = [finding, ...findings];
      return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(finding) });
    }
    const findingMatch = path.match(/^\/threat-hunting\/hunts\/([^/]+)\/findings\/([^/]+)$/);
    if (findingMatch && route.request().method() === 'PATCH') {
      const body = route.request().postDataJSON();
      const hunt = hunts.find(item => item.id === findingMatch[1]);
      const index = findings.findIndex(item => item.id === findingMatch[2] && item.hunt_id === findingMatch[1] && !item.archived_at);
      if (!hunt || index < 0) return apiError(404, 'Threat hunt finding not found');
      if (!mutableHuntStatuses.includes(hunt.status)) return apiError(409, `Hunt is ${hunt.status} and its evidence record is read-only`);
      if (body.title !== undefined && String(body.title).trim().length < 3) return apiError(422, 'String should have at least 3 characters');
      if (body.evidence_type !== undefined && String(body.evidence_type).trim().length < 2) return apiError(422, 'String should have at least 2 characters');
      if (body.technique_ids && invalidTechnique(body.technique_ids)) return apiError(422, 'Invalid ATT&CK technique IDs');
      if (body.tlp && (isTlpDowngrade(hunt.tlp, body.tlp) || isTlpDowngrade(findings[index].tlp, body.tlp))) return apiError(422, 'TLP cannot be downgraded');
      if (body.query_version_id && !queryVersions.some(item => item.id === body.query_version_id && item.hunt_id === hunt.id)) return apiError(422, 'query_version_id does not belong to this hunt');
      findings[index] = { ...findings[index], ...body, updated_at: '2026-07-17T09:25:00Z' };
      return json(findings[index]);
    }
    const findingArchiveMatch = path.match(/^\/threat-hunting\/hunts\/([^/]+)\/findings\/([^/]+)\/archive$/);
    if (findingArchiveMatch && route.request().method() === 'POST') {
      const hunt = hunts.find(item => item.id === findingArchiveMatch[1]);
      const index = findings.findIndex(item => item.id === findingArchiveMatch[2] && item.hunt_id === findingArchiveMatch[1] && !item.archived_at);
      if (!hunt || index < 0) return apiError(404, 'Threat hunt finding not found');
      if (!mutableHuntStatuses.includes(hunt.status)) return apiError(409, `Hunt is ${hunt.status} and its evidence record is read-only`);
      findings[index] = { ...findings[index], archived_at: '2026-07-17T09:30:00Z', updated_at: '2026-07-17T09:30:00Z' };
      return json(findings[index]);
    }
    return json({});
  });
}
