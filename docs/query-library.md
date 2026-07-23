# Threat Hunting Query Library

The Query Library turns detection content into a searchable, source-backed
starting point for threat hunts. It combines reviewed AdversaryGraph examples
with rules imported through Pipeline from SigmaHQ, Yara-Rules, the Google
SecOps community YARA-L repository, and operator-managed Git or raw-file
sources.

It is a drafting and review system. It does not execute queries, validate them
against a customer SIEM, or establish that a rule is appropriate for a specific
environment.

## Open the library

Select **Hunt & Validate → Query Library**. The page provides:

- catalog metrics, server-side search, and typed autocomplete;
- filters for language, ATT&CK technique, tag, source, platform, and IOC type;
- rule quality/parser state, source, license, and upstream links;
- direct ATT&CK links for every mapped technique;
- query preview, copy, and **Create hunt from query** actions; and
- the deterministic **Build query from IOCs** workflow.

The built-in catalog contains more than thirty reviewed Sigma and YARA-L
starting points. Community sync expands the catalog to the bounded limits
configured on each Pipeline source.

## Smart search

Ordinary terms search titles, descriptions, query content, tags, techniques,
and source names. Multiple terms are combined so every term must match. Quoted
phrases remain one term.

| Filter | Example | Meaning |
|---|---|---|
| tag | <code>tag:persistence</code> | Match a normalized tag |
| technique / ttp / attack | <code>ttp:T1059.001</code> | Match ATT&CK |
| language / lang | <code>lang:yaral</code> | Match a query format |
| source | <code>source:"SigmaHQ Rules"</code> | Match provenance |
| platform | <code>platform:Windows</code> | Match a platform |
| ioc / type | <code>ioc:domain</code> | Match IOC-oriented examples |

Autocomplete proposes typed values already present in the catalog and includes
their result counts. Server-side filters remain authoritative; the browser does
not download the whole corpus to search it.

## Community and Git-backed content

The default sources are SigmaHQ's main rules tree, Yara-Rules' malware rules,
and the Apache-2.0 Google SecOps community YARA-L rules tree.

Open **Pipeline**, select **Add default rule feeds**, and run the desired
source. A successful run writes source-backed detection versions and refreshes
the Query Library index. Existing deployments can select **Index community
rules** in Query Library to import already-stored versions without downloading
anything.

Imported items preserve source name and URL, upstream rule ID, format, rule
content, parsed ATT&CK IDs, validation details, and last synchronization time.
Feed fetches remain bounded by each source's <code>config.limit</code>.
Provenance-derived stable keys update existing records instead of duplicating
them on every sync.

## Build a query from IOCs

1. Select **Build query from IOCs**.
2. Enter one IOC per line. Automatic types include IPv4/IPv6, domains, URLs,
   email, MD5, SHA-1, and SHA-256.
3. Optionally prefix a value with a type, such as
   <code>ip:203.0.113.10</code>.
4. Choose Sigma, YARA-L, YARA, KQL, SPL, EQL, Lucene, SQL, osquery, or generic
   output.
5. Add only ATT&CK IDs supported by investigation evidence.
6. Build, review, and copy the result or create a hunt draft.

IOC generation is deterministic and local. It escapes values, groups them by
type, selects format-specific field mappings, and does not send indicators to
an LLM. When stored IOC IDs are supplied through the API, only their stored
ATT&CK mappings are carried into the result.

Example request:

    curl -sS -X POST http://localhost:3000/api/query-library/build-from-ioc \
      -H 'Content-Type: application/json' \
      -d '{"title":"Known infrastructure review","language":"yaral",
           "observables":[{"value":"203.0.113.10","type":"ip"},
                          {"value":"malicious.example","type":"domain"}],
           "technique_ids":["T1071.001"]}'

## Threat-hunt handoff

**Create hunt from query** opens a canonical Threat Hunting draft and prefills
its title, description, query text and language, ATT&CK mappings, tags, data
sources, provenance context, hypothesis shell, and validation assumptions.
The analyst must still define scope, time range, required fields, expected
evidence, exclusions, owner, and TLP.

The handoff never executes the query and never records a finding. Query changes
are versioned only after saving through the normal Threat Hunting workflow.

## Production review checklist

Before running or deploying a library query:

1. Confirm the upstream rule is current and review its license.
2. Confirm the ATT&CK mapping is supported by the rule behavior.
3. Translate generic fields to the destination schema.
4. Confirm required logs, parsers, retention, and timestamps exist.
5. Add environment-specific allowlists and false-positive controls.
6. Validate syntax in the destination product.
7. Test against known-positive and representative benign data.
8. Bound the time range and expected result volume.
9. Preserve the reviewed version, evidence references, and outcome in the hunt.

For YARA-L, validate UDM fields and test in Google SecOps. For Sigma, validate
the source rule and converted backend query separately. YARA matches file
content; it is not interchangeable with YARA-L log correlation.

## API and permissions

- <code>GET /api/query-library</code>
- <code>GET /api/query-library/facets</code>
- <code>GET /api/query-library/autocomplete?q=</code>
- <code>GET /api/query-library/{item_id}</code>
- <code>POST /api/query-library/build-from-ioc</code>
- <code>POST /api/query-library/sync</code>

Reading, searching, and IOC drafting require <code>run_analysis</code>.
Indexing stored community detection versions requires
<code>manage_feeds</code>.
