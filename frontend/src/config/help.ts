export type HelpTopic = {
  id: string;
  title: string;
  route: string;
  aliases?: string[];
  summary: string;
  whenToUse: string[];
  workflow: string[];
  outputs: string[];
  tips: string[];
};

export const helpTopics: HelpTopic[] = [
  {
    id: 'discover',
    title: 'Discover Intelligence',
    route: '/discover',
    summary: 'The platform start page for jumping into actors, reports, IOCs, malware, asset exposure, attack simulation, and saved investigations.',
    whenToUse: ['Start a new investigation', 'Open the main workflows from one place', 'Check platform health, enabled APIs, and feed status'],
    workflow: ['Review the action cards and counters', 'Use IOC quick actions for direct pivoting', 'Open the relevant module from the launcher', 'Run self-test if the environment looks incomplete'],
    outputs: ['Fast navigation into investigation workflows', 'Current platform counters', 'API and feed readiness signals'],
    tips: ['If a workflow returns empty results, open Feeds Management and sync sources first.', 'Use the sidebar search for direct actor, technique, IOC, and CVE lookup.'],
  },
  {
    id: 'navigator',
    title: 'Navigator',
    route: '/navigator',
    summary: 'ATT&CK and ATLAS matrix workspace for selecting techniques, reviewing sub-techniques, and building coverage or simulation context.',
    whenToUse: ['Select TTPs for comparison, coverage, or reporting', 'Review technique context across Enterprise, Mobile, ICS, and ATLAS', 'Find techniques with attack simulation support'],
    workflow: ['Choose the domain from the header', 'Expand tactics and techniques as needed', 'Select techniques or sub-techniques', 'Open details or continue into Compare, Attack Simulation, or reports'],
    outputs: ['Selected TTP set', 'Technique details and references', 'Matrix view with simulation and coverage signals'],
    tips: ['Use the domain switcher before selecting techniques.', 'Simulation-enabled techniques are marked in the matrix and link to Attack Simulation.'],
  },
  {
    id: 'apt-library',
    title: 'ATT&CK Group Library',
    route: '/apt',
    aliases: ['ATT&CK Group Library'],
    summary: 'Actor library backed by ATT&CK, reports, aliases, techniques, IOCs, campaigns, and CVE correlations.',
    whenToUse: ['Research an APT or intrusion set', 'Load an actor technique set into the workspace', 'Review evidence, IOCs, reports, and CVEs connected to a group'],
    workflow: ['Search or select a group', 'Review overview, techniques, reports, IOCs, and CVEs', 'Load the actor TTPs when needed', 'Copy links or track the actor for follow-up'],
    outputs: ['Actor profile', 'Mapped techniques', 'Related reports, IOCs, campaigns, and CVEs'],
    tips: ['Technique overlap is an investigative lead, not attribution proof.', 'Use Compare after loading actor TTPs to inspect similarity and gaps.'],
  },
  {
    id: 'ai-analysis',
    title: 'AI Analysis',
    route: '/analyze',
    summary: 'LLM-assisted report analysis for extracting ATT&CK evidence, IOCs, actor mentions, and analyst-ready summaries.',
    whenToUse: ['Turn CTI reports into structured candidates', 'Extract evidence-backed TTP mappings', 'Prepare report-derived outputs for detection engineering'],
    workflow: ['Paste or upload report content', 'Choose the configured LLM provider', 'Run analysis', 'Review evidence, confidence, gaps, and extracted observables'],
    outputs: ['TTP candidates with evidence', 'IOC candidates', 'Summary and validation gaps', 'Exportable analyst output'],
    tips: ['Always validate AI mappings against the source text.', 'Use local or private gateways for sensitive reports.'],
  },
  {
    id: 'compare',
    title: 'Compare',
    route: '/compare',
    summary: 'Compares selected techniques against groups, campaigns, reports, or another group to find overlap, gaps, and likely investigation leads.',
    whenToUse: ['Compare selected TTPs to known actors', 'Prioritize coverage gaps', 'Review similarity without making attribution claims'],
    workflow: ['Select techniques in Navigator or load them from an actor', 'Choose Groups, Campaigns, Reports, or Group vs Group', 'Run comparison', 'Review overlap, missing techniques, and evidence'],
    outputs: ['Similarity ranking', 'Technique overlap', 'Coverage gaps', 'Comparison explanation'],
    tips: ['No selected techniques means the page will wait for Navigator input.', 'Use results as hypotheses for further validation, not as proof of attribution.'],
  },
  {
    id: 'sector-intel',
    title: 'Sector Intel',
    route: '/sector-intel',
    summary: 'Sector-oriented intelligence view for filtering relevant actors, techniques, regions, technologies, and defensive priorities.',
    whenToUse: ['Build an industry-specific threat picture', 'Prioritize TTPs for a vertical', 'Prepare sector detection coverage'],
    workflow: ['Select sector and context filters', 'Review relevant actors and techniques', 'Open actor or technique details', 'Export or continue into Compare and Navigator'],
    outputs: ['Sector threat overview', 'Relevant actors and TTPs', 'Prioritized investigation leads'],
    tips: ['Treat sector relevance as context; validate with current reporting and internal telemetry.'],
  },
  {
    id: 'asset-surface',
    title: 'Asset Attack Surface',
    route: '/asset-surface',
    summary: 'Normalizes asset inventory files and maps exposed services, identities, cloud resources, and weak points to likely ATT&CK techniques.',
    whenToUse: ['Upload CMDB, scanner, cloud, or hostname/IP inventory', 'Map asset exposure to TTPs', 'Create saved asset attack-surface cases'],
    workflow: ['Name the inventory', 'Paste or upload CSV, JSON, TXT, scanner, or cloud inventory', 'Choose AI enrichment if configured', 'Run analysis and review mapped assets, TTPs, risk, and telemetry readiness'],
    outputs: ['Attack surface matrix', 'Asset-to-TTP mapping', 'Telemetry Readiness Score', 'Saved asset cases'],
    tips: ['Inventory-based TTPs are hypotheses until validated against reachable services and telemetry.', 'Use Telemetry Readiness Score to find detection blind spots.'],
  },
  {
    id: 'attack-simulation',
    title: 'Attack Simulation',
    route: '/attack-simulation',
    summary: 'Authorized simulation workspace for generating TTP-specific lab telemetry, forwarding it to SIEM, and validating detection logic.',
    whenToUse: ['Validate SIEM rules with TTP-specific telemetry', 'Run approved lab web, endpoint, auth, DNS, proxy, WAF, and EDR-style flows', 'Generate AI-assisted kill-chain challenges'],
    workflow: ['Choose a TTP or scenario from the matrix/library', 'Configure approved lab target and SIEM destination', 'Run the simulation or AI assistant flow', 'Watch logs, expand attack-chain steps, and resend saved flows'],
    outputs: ['Real lab server logs where supported', 'Vendor/source-shaped simulated events for atomic telemetry gaps', 'Attack chain graph', 'SIEM forwarding result'],
    tips: ['Use only approved lab targets.', 'Correct telemetry is required: unsupported techniques should be shown as telemetry gaps, not generic fake logs.'],
  },
  {
    id: 'evidence-graph',
    title: 'Evidence Graph',
    route: '/evidence-graph',
    summary: 'Graph view for connecting evidence, claims, techniques, detections, validation gaps, and investigation decisions.',
    whenToUse: ['Trace why a TTP was selected', 'Show evidence-to-detection reasoning', 'Review investigation decision paths'],
    workflow: ['Open or create an investigation context', 'Review evidence nodes and linked claims', 'Inspect connected TTPs, detections, IOCs, and validation gaps', 'Use the graph for reporting or analyst review'],
    outputs: ['Evidence chain', 'Claim-to-TTP links', 'Detection and gap context'],
    tips: ['Keep weak evidence visible as a gap instead of hiding it.', 'Use this page when handing work to another analyst.'],
  },
  {
    id: 'ioc-library',
    title: 'IOC Library',
    route: '/ioc-library',
    aliases: ['IOC Library', 'IOC Detail', 'IOC Node Detail'],
    summary: 'Searchable IOC repository with enrichment, sources, actor/TTP/CVE links, and STIX-oriented export context.',
    whenToUse: ['Search IPs, domains, URLs, hashes, and malware family names', 'Review enrichment and source evidence', 'Pivot from indicators to actors, techniques, reports, and CVEs'],
    workflow: ['Search or filter indicators', 'Open an IOC detail page', 'Review enrichment, sources, links, and confidence', 'Pivot into IOC Investigation or actor/CVE pages'],
    outputs: ['IOC records', 'Source-backed enrichment', 'Crosslinks to actors, TTPs, CVEs, and reports'],
    tips: ['Do not treat raw IOC overlap as attribution proof.', 'Refresh feeds when source timestamps are stale.'],
  },
  {
    id: 'ioc-investigation',
    title: 'IOC Investigation',
    route: '/ioc-investigation',
    summary: 'Pivot workspace for building an investigation around an IOC, enrichment trail, graph, related TTPs, actors, and summary.',
    whenToUse: ['Investigate one suspicious observable', 'Build pivot chains from enrichment results', 'Prepare IOC-to-TTP or IOC-to-actor context'],
    workflow: ['Enter an IOC or open from IOC Library', 'Run enrichment and pivots', 'Review graph, sources, related entities, and risk', 'Save or export the investigation'],
    outputs: ['IOC investigation graph', 'Related entities', 'AI summary', 'Pivot trail'],
    tips: ['Separate source evidence from inferred relationships.', 'Record why each pivot is relevant.'],
  },
  {
    id: 'cve-library',
    title: 'CVE Library',
    route: '/cve',
    summary: 'CVE intelligence workspace with CVSS, CISA KEV, weaknesses, affected product context, and strict CVE-TTP-APT-IOC relationship review.',
    whenToUse: ['Prioritize vulnerabilities by CVSS and KEV status', 'Map exploited CVEs to techniques and actors', 'Review vulnerability exposure in investigations'],
    workflow: ['Search or filter CVEs', 'Open a CVE detail panel', 'Review CVSS, KEV, weakness, product, and correlations', 'Validate linked TTPs, actors, and IOCs'],
    outputs: ['CVE records', 'CVSS and KEV context', 'CVE-to-TTP/APT/IOC links'],
    tips: ['Unknown CVSS usually means the source record lacks enough scoring data.', 'Exploitability and exposure still need asset-side validation.'],
  },
  {
    id: 'feeds',
    title: 'Feeds Management',
    route: '/feeds',
    summary: 'Feed control center for ATT&CK, IOC, CVE, malware, report, and external enrichment sources.',
    whenToUse: ['Sync or troubleshoot data sources', 'Check API key readiness', 'Review feed timestamps and degraded sources'],
    workflow: ['Review enabled sources and status', 'Run selected syncs', 'Open errors or degraded sources', 'Confirm counters changed after sync'],
    outputs: ['Feed sync status', 'Source errors', 'Indicator, CVE, and report counts'],
    tips: ['Use this page first when library pages look empty.', 'API timeout does not always mean data is missing; check the last successful sync timestamp.'],
  },
  {
    id: 'malware-analysis',
    title: 'Malware Analysis',
    route: '/malware-analysis',
    summary: 'Safe malware triage workspace for sample cases, hashes, strings, IOCs, TTP candidates, first analysis, and AI summaries.',
    whenToUse: ['Create a malware analysis case', 'Upload or review a sample safely', 'Extract hashes, strings, imports, suspicious APIs, IOCs, and TTP leads'],
    workflow: ['Create or select a case', 'Upload a sample or use an existing sample reference', 'Run first analysis and hash/feed checks', 'Review summary, validation gaps, and linked debug workflows'],
    outputs: ['Case summary', 'Hashes and strings', 'IOC and TTP candidates', 'AI malware summary'],
    tips: ['First analysis is not a sandbox verdict.', 'Use Debugger and Dynamic Analysis for deeper control-flow and runtime validation.'],
  },
  {
    id: 'debugger',
    title: 'Decompilation & Debug IDE',
    route: '/malware-debug',
    aliases: ['Decompilation & Debug IDE', 'Debugger'],
    summary: 'IDE-style malware reverse engineering view with decompilation, entrypoint details, APIs, strings, sections, function stepping, and AI explanations.',
    whenToUse: ['Inspect recovered pseudocode and entrypoint context', 'Step through functions and request AI function summaries', 'Understand static control-flow and suspicious APIs'],
    workflow: ['Choose the analysis job and target', 'Load decompilation or create a debug workspace', 'Step functions or run all functions', 'Open AI debug summary and validation gaps'],
    outputs: ['Pseudocode view', 'Function graph', 'API/string/section context', 'AI function summaries'],
    tips: ['Static decompilation can be wrong for packed samples.', 'Treat runtime-only behavior as unproven until a safe dynamic profile confirms it.'],
  },
  {
    id: 'dynamic-analysis',
    title: 'Dynamic Analysis',
    route: '/dynamic-analysis',
    summary: 'Runtime behavior review for process, file, registry, network, DNS, API, memory, module, persistence, command, and branch-decision evidence.',
    whenToUse: ['Review runtime behavior after safe execution or collected telemetry', 'Summarize what malware does from dynamic evidence', 'Separate observed behavior from static guesses'],
    workflow: ['Open a sample case', 'Review runtime categories', 'Inspect evidence and gaps', 'Generate AI dynamic analysis summary'],
    outputs: ['Behavior timeline', 'Runtime artifact categories', 'AI dynamic summary', 'Validation gaps'],
    tips: ['Only observed runtime events should be marked as executed.', 'Use isolated, disposable runtime profiles for unsafe samples.'],
  },
  {
    id: 'string-analyzer',
    title: 'String Analyzer',
    route: '/string-analyzer',
    summary: 'Extracts and classifies strings, commands, URLs, registry keys, APIs, file paths, and IOC/TTP leads from samples or text.',
    whenToUse: ['Quickly triage strings from a sample', 'Find commands, URLs, registry keys, and API names', 'Generate leads for malware analysis and detection'],
    workflow: ['Paste text or load a sample string set', 'Run extraction', 'Review classified strings and findings', 'Send relevant leads into analysis or IOC workflows'],
    outputs: ['Classified strings', 'IOC candidates', 'Suspicious API and command leads'],
    tips: ['Strings are weak evidence by themselves.', 'Correlate strings with imports, code references, or runtime evidence.'],
  },
  {
    id: 'operations',
    title: 'Operations',
    route: '/operations',
    summary: 'Operational workspace for investigations, intake, detections, tracked actors, and analyst workflow objects.',
    whenToUse: ['Manage active investigations', 'Track detections and actors', 'Organize analyst workflow state'],
    workflow: ['Create or open investigation objects', 'Update intake, detections, and tracked actors', 'Review linked evidence and status', 'Close or export when complete'],
    outputs: ['Investigation records', 'Detection skeletons', 'Tracked actor state'],
    tips: ['Use consistent naming and tags so cases remain searchable.'],
  },
  {
    id: 'pipeline',
    title: 'Pipeline',
    route: '/pipeline',
    summary: 'Pipeline builder for source intake, observable processing, idempotent upsert, and detection skeleton generation.',
    whenToUse: ['Create structured intake sources', 'Normalize observables', 'Generate detection starting points from pipeline data'],
    workflow: ['Create or update a source', 'Add observables', 'Review validation and duplicates', 'Generate detection skeletons where appropriate'],
    outputs: ['Sources', 'Observables', 'Detection skeletons'],
    tips: ['Use source kind validation to avoid mixing incompatible data types.'],
  },
  {
    id: 'statistics',
    title: 'Statistics',
    route: '/statistics',
    summary: 'Statistical analysis workspace for comparing actors, reports, sectors, TTP usage, CVE usage, IOC coverage, and cross-dataset technique pressure.',
    whenToUse: ['Compare behavior frequency across groups and reports', 'Measure which TTPs, CVEs, sectors, and IOC sources dominate the knowledge base', 'Select specific datasets with checkboxes for focused statistical analysis'],
    workflow: ['Choose datasets to include with the checkboxes', 'Set row limit for each widget', 'Review totals, charts, and ranked tables', 'Click TTP, actor, CVE, or CWE rows to pivot into the relevant module'],
    outputs: ['Actor and campaign TTP coverage statistics', 'Report-extracted TTP frequency', 'CVE severity, KEV, weakness, and TTP linkage statistics', 'IOC type/source/TTP statistics', 'Sector confidence and actor mention statistics'],
    tips: ['Statistics show coverage and frequency in your local data. They do not prove attribution or exploitation without source evidence.'],
  },
  {
    id: 'observability',
    title: 'Observability',
    route: '/observability',
    summary: 'Operational health view for API health, logs, request traces, route metrics, readiness, and Prometheus-style signals.',
    whenToUse: ['Troubleshoot a local Docker deployment', 'Check route errors and slow requests', 'Review logs and platform health'],
    workflow: ['Open health and metrics panels', 'Review recent logs and traces', 'Filter by route or status', 'Use Troubleshooting for remediation steps'],
    outputs: ['Health status', 'Route metrics', 'Log tail', 'Trace summaries'],
    tips: ['Use this page before restarting containers blindly.', 'Redact secrets before sharing logs.'],
  },
  {
    id: 'admin',
    title: 'Admin Panel',
    route: '/admin',
    aliases: ['Admin Users'],
    summary: 'Administrative control panel for users, roles, password reset, sessions, MFA workflow state, and audit history.',
    whenToUse: ['Manage local users and permissions', 'Review session and audit state', 'Reset passwords or revoke access'],
    workflow: ['Open Admin Panel as an admin', 'Create or update users and roles', 'Review sessions and audit records', 'Apply password or session actions'],
    outputs: ['User and role state', 'Session records', 'Audit events'],
    tips: ['Use least privilege for daily analyst work.', 'Rotate local admin credentials after first deployment.'],
  },
  {
    id: 'troubleshooting',
    title: 'Troubleshooting',
    route: '/troubleshooting',
    summary: 'Guided diagnostics for Docker, API, database, feed sync, auth, local browser, and module-specific errors.',
    whenToUse: ['Fix failed API calls', 'Understand self-test errors', 'Recover broken local deployment or feed sync'],
    workflow: ['Read the failing symptom', 'Run the suggested check', 'Apply the smallest remediation', 'Re-run self-test or the failing module action'],
    outputs: ['Diagnostic commands', 'Known error explanations', 'Recovery steps'],
    tips: ['Check container health before changing application data.', 'Preserve volumes unless you intentionally want a clean environment.'],
  },
  {
    id: 'auth',
    title: 'Auth Guide',
    route: '/auth-guide',
    summary: 'Local authentication guide covering login, users, roles, session behavior, admin controls, and deployment defaults.',
    whenToUse: ['Enable native auth', 'Understand viewer, analyst, and admin permissions', 'Troubleshoot login or session behavior'],
    workflow: ['Review auth mode and environment variables', 'Login with a configured user', 'Manage users from Admin Panel', 'Review sessions and audit events'],
    outputs: ['Auth configuration guidance', 'Role model', 'Admin workflow'],
    tips: ['Do not expose default credentials in production.', 'Prefer SSO/OIDC for enterprise deployments when available.'],
  },
  {
    id: 'help',
    title: 'Help / Local Guide',
    route: '/help',
    aliases: ['Help'],
    summary: 'Complete local running guide and module-by-module platform manual.',
    whenToUse: ['Learn how to run the platform locally', 'Find what each module does', 'Open the full guide from any page help popup'],
    workflow: ['Read Quick Start for local deployment', 'Use Module Guides for workflow details', 'Open module pages from the guide links', 'Use Troubleshooting when health checks fail'],
    outputs: ['Local runbook', 'Module user guides', 'Operational tips'],
    tips: ['Keep this page open when evaluating the platform or onboarding a new analyst.'],
  },
];

export const localRunSections = [
  {
    title: 'Local Docker quick start',
    body: [
      'Clone the repository and enter the project directory.',
      'Copy .env.example to .env and fill only the providers you plan to use. Empty provider keys are acceptable for offline/local workflows.',
      'Start the stack with: docker compose up -d --build',
      'Open http://localhost:3000 and wait for the startup health screen to clear.',
    ],
  },
  {
    title: 'Health and self-test',
    body: [
      'The frontend waits for API readiness before opening the workspace.',
      'Use the Self-test button to validate database, Redis, ATT&CK data, CVE/IOC sync state, API keys, CPU, memory, and route health.',
      'For terminal checks, use docker compose ps and docker compose logs -f api frontend worker beat.',
    ],
  },
  {
    title: 'Authentication',
    body: [
      'When auth is enabled, the first screen is the login page and protected pages require a valid session.',
      'Admin Panel manages local users, roles, sessions, MFA workflow state, password reset, and audit records.',
      'Viewer can read, analyst can run analysis/simulation workflows, and admin can manage users and protected operations.',
    ],
  },
  {
    title: 'Data and feeds',
    body: [
      'Feeds Management controls ATT&CK, IOC, CVE, malware, report, and enrichment source synchronization.',
      'Most modules work offline with bundled data, but external enrichment requires API keys and successful source sync.',
      'If pages look empty, check feed status before changing code or clearing data.',
    ],
  },
  {
    title: 'Attack simulation safety',
    body: [
      'Attack Simulation is for authorized lab validation only.',
      'Real lab telemetry is preferred where a lab service exists. Atomic source-shaped events must match the real vendor/system event structure.',
      'SIEM forwarding credentials are used only for the request; saved destinations store address history, not secrets.',
    ],
  },
  {
    title: 'Update and stop',
    body: [
      'Update with git pull followed by docker compose up -d --build.',
      'Stop with docker compose down. This keeps volumes unless you explicitly remove them.',
      'Back up database and persistent volumes before major upgrades or destructive testing.',
    ],
  },
];

const normalize = (value: string) => value.trim().toLowerCase();

export function getHelpTopicByTitle(title: string): HelpTopic {
  const normalizedTitle = normalize(title);
  return (
    helpTopics.find(topic => normalize(topic.title) === normalizedTitle || topic.aliases?.some(alias => normalize(alias) === normalizedTitle)) ??
    helpTopics.find(topic => normalizedTitle.includes(normalize(topic.title)) || topic.aliases?.some(alias => normalizedTitle.includes(normalize(alias)))) ??
    helpTopics[0]
  );
}

export function getHelpTopicByPath(pathname: string): HelpTopic {
  const exact = helpTopics.find(topic => pathname === topic.route || pathname.startsWith(`${topic.route}/`));
  if (exact) return exact;
  if (pathname.startsWith('/ioc-node')) return helpTopics.find(topic => topic.id === 'ioc-library') ?? helpTopics[0];
  if (pathname.startsWith('/debugger')) return helpTopics.find(topic => topic.id === 'debugger') ?? helpTopics[0];
  return helpTopics[0];
}
