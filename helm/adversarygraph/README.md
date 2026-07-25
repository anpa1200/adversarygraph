# AdversaryGraph Helm Chart

This v6.5 chart is a deployment scaffold for a controlled, single-workspace
Kubernetes installation. Production use requires the image digests and manifest
produced by the successful v6.5.0 tag workflow; source metadata or human-readable
tags alone are not release evidence. It is not a managed-SaaS or multi-tenant
isolation boundary.

## Prerequisites

- Kubernetes 1.27 or newer
- Helm 3
- a default StorageClass, or explicit storage classes for every PVC
- an ingress controller and certificate workflow when TLS ingress is enabled
- an externally managed Secret for any production-like installation
- digest-pinned `pgvector/pgvector:0.8.2-pg16` is the development/evaluation
  default; production uses the release's custom pgvector-capable
  `adversarygraph-postgres` image and reviewed digest. An external database
  overlay must provide pgvector 0.5.0 or newer before API startup.

The bundled chart deploys PostgreSQL and Redis. Setting either bundled service
to `enabled: false` requires a deployment-specific chart overlay that supplies
the external host/URL and removes the corresponding internal-service
assumptions; the base values do not configure managed database endpoints.

## Secrets

The chart does not render placeholder credentials by default. Create a Secret
first and point `secrets.existingSecret` to it. The Secret must contain these
keys:

- `DB_NAME`, `DB_USER`, `DB_PASS`, `REDIS_PASSWORD`, and
  `RATE_LIMIT_PROXY_SECRET`;
- `AUTH_BOOTSTRAP_ADMIN_PASSWORD` during first bootstrap only;
- `PROXY_SECRET` when trusted reverse-proxy SSO is enabled;
- only the provider keys the deployment uses, such as `OPENAI_API_KEY`,
  `GEMINI_API_KEY`, or `LOCAL_LLM_API_KEY`.

Other optional key names are listed in `templates/secret.yaml`. Missing optional
keys are acceptable for the API, worker, and beat, which load the runtime Secret
with `envFrom`. MalwareGraph receives only `MALWAREGRAPH_API_KEY` from that
Secret, so it is not given unrelated database, identity, or provider
credentials. The database/Redis keys and rate-limit proxy secret above are
required by direct references.

Redis credentials must be at least 24 characters and contain only letters,
digits, underscores, or hyphens because the value is embedded in a Redis URI.
`RATE_LIMIT_PROXY_SECRET` has the same length and character-set requirement so
the frontend can pass it safely as a single header value.
For an auth-enabled installation, the externally managed Secret must also
contain a first-start `AUTH_BOOTSTRAP_ADMIN_PASSWORD` or a `PROXY_SECRET`, unless
this is an upgrade with an already verified named administrator. Helm cannot
inspect an existing Secret's contents, so validate these contracts before
installing. If you deliberately clear `secrets.existingSecret`, template
rendering enforces equivalent chart-managed requirements; only a verified
upgrade may set `config.authExistingAdminConfirmed: "true"` instead.

Example:

```bash
kubectl create namespace adversarygraph
kubectl -n adversarygraph create secret generic adversarygraph-runtime \
  --from-literal=DB_NAME=adversarygraph \
  --from-literal=DB_USER=ag_user \
  --from-literal=DB_PASS="$(openssl rand -hex 32)" \
  --from-literal=REDIS_PASSWORD="$(openssl rand -hex 32)" \
  --from-literal=RATE_LIMIT_PROXY_SECRET="$(openssl rand -hex 32)" \
  --from-literal=AUTH_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 24)"
```

## Render and Validate

Create a reviewed values file containing at least:

```yaml
secrets:
  existingSecret: adversarygraph-runtime
config:
  productionMode: "true"
  corsAllowedOrigins: https://adversarygraph.example.com
  secureCookies: "true"
ingress:
  enabled: true
  className: nginx
  host: adversarygraph.example.com
  tlsSecretName: adversarygraph-tls
```

Then validate before installation:

```bash
helm lint ./helm/adversarygraph -f values.prod.yaml
helm template adversarygraph ./helm/adversarygraph \
  --namespace adversarygraph -f values.prod.yaml > rendered.yaml
```

Review `rendered.yaml` without committing it: confirm image tags, Secret names,
PVC/storage classes, resource limits, CORS origin, secure cookies, ingress TLS,
pod security contexts, and the rendered NetworkPolicies.

`config.productionMode: "true"` is fail-closed. Rendering then requires native
authentication, secure cookies, explicit HTTPS CORS origins, the baseline
NetworkPolicies, an externally managed Secret, reviewed backend/frontend and
enabled-MalwareGraph digests, the custom remediated PostgreSQL repository and
digest, and a Redis digest. This validates chart values, not the contents of an
existing Secret or the registry provenance of a syntactically valid digest;
review both separately.

### Image integrity

The backend, frontend, and MalwareGraph images default to the versioned
`6.5.0` tags with empty digest fields and `imagePullPolicy: Always`. PostgreSQL
uses the pgvector project's `0.8.2-pg16` compatibility image so the development
chart has the extension required by the RAG schema; both PostgreSQL and Redis
compatibility images are digest-pinned. Do not deploy the application tags
until the matching tag workflow publishes and verifies them. For production,
use the release manifest, replace the PostgreSQL
compatibility image with the release's custom image and use the digest manifest
created by that revision's successful tag workflow. A configured digest takes
precedence over its human-readable tag:

```yaml
image:
  digest: sha256:<64-lowercase-hex-characters>
postgresql:
  image:
    repository: ghcr.io/anpa1200/adversarygraph-postgres
    digest: sha256:<64-lowercase-hex-characters>
frontend:
  image:
    digest: sha256:<64-lowercase-hex-characters>
malwaregraph:
  image:
    digest: sha256:<64-lowercase-hex-characters>
```

Do not copy example or cross-architecture digests. Resolve custom-image digests
from the exact release's attached `adversarygraph-images.env`, verify the
registry and platform, and record their provenance. Refresh the compatibility
PostgreSQL and Redis pins under the deployment's vulnerability-management
policy for non-production chart evaluation; do not substitute that upstream
PostgreSQL pin for the remediated release image in a gated rollout.

### Network policy

`networkPolicy.enabled: true` creates a baseline ingress policy for every chart
pod. The API accepts port 8000 only from this release's frontend; PostgreSQL,
Redis, and MalwareGraph accept their service ports only from the components
that use them; worker and beat admit no pod ingress. The frontend admits port
8080 from any source because ingress-controller namespace and pod labels are
cluster-specific.

Egress is intentionally not restricted by the base chart. ATT&CK/ATLAS, CTI,
vulnerability, IOC, and optional model providers have deployment-specific
destinations, and a portable allowlist would either break supported workflows
or provide misleading protection. Add reviewed DNS and egress rules in the
cluster policy layer. Use `networkPolicy.extraIngress.<component>` for
additional raw ingress rules required by monitoring or backup workloads. For
example, a PostgreSQL backup job must be explicitly allowed by its pod labels.
Disable the baseline only when an equivalent namespace or CNI policy is already
enforced and documented.

The chart defaults every PVC to `ReadWriteOnce` for compatibility with common
single-node storage classes. The ATT&CK data and log PVCs are shared by API,
worker, and beat, and MalwareGraph storage is shared by API and MalwareGraph.
For replicas scheduled across multiple nodes, select an RWX-capable class and
configure the shared claims explicitly:

```yaml
postgresql:
  storageClassName: fast-rwo
  accessModes: [ReadWriteOnce]
malwaregraph:
  storageClassName: shared-rwx
  accessModes: [ReadWriteMany]
persistence:
  attckData:
    storageClassName: shared-rwx
    accessModes: [ReadWriteMany]
  logs:
    storageClassName: shared-rwx
    accessModes: [ReadWriteMany]
```

If the cluster has no RWX class, keep `ReadWriteOnce` and deliberately constrain
all consumers of each shared claim to the same node. Do not scale replicas
across nodes and hope the scheduler can attach a single-node volume twice.

## Install and Verify

```bash
helm upgrade --install adversarygraph ./helm/adversarygraph \
  --namespace adversarygraph --create-namespace \
  --atomic --timeout 15m -f values.prod.yaml
kubectl -n adversarygraph rollout status deployment/adversarygraph-api
kubectl -n adversarygraph rollout status deployment/adversarygraph-frontend
```

The API liveness probe uses `/api/health`; readiness uses `/api/ready` and does
not admit traffic until PostgreSQL responds. The frontend receives the
release-qualified API Service through `API_UPSTREAM`.

`config.localLlmBaseUrl` is empty by default because Kubernetes does not
portably resolve Compose's `host.docker.internal` hostname. To enable the local
provider, set it to an OpenAI-compatible in-cluster Service URL or a reviewed
private gateway that is reachable from API, worker, and MalwareGraph pods.

## Unified RAG Configuration

The v6.5 chart templates enable RAG configuration and scheduled reconciliation
by default, while semantic embeddings remain disabled. Use revision-matched
backend and frontend application images; worker and Beat use the backend image.
The digest-pinned
PostgreSQL evaluation default already includes pgvector 0.8.2. Production also
replaces that compatibility image with the release's reviewed PostgreSQL image
and digest. With revision-matched application images, exact identifier and
PostgreSQL full-text retrieval work without a model dependency. A production
values overlay can enable the reviewed private vector path:

```yaml
config:
  ragEnabled: "true"
  localLlmBaseUrl: http://private-model.ai-services.svc.cluster.local:11434/v1
  localLlmModel: llama3.1:8b
  ragEmbeddingEnabled: "true"
  ragEmbeddingProvider: local
  ragEmbeddingModel: nomic-embed-text
  ragEmbeddingDimensions: "768"
  ragEmbeddingBatchSize: "32"
  ragVectorMaxCosineDistance: "0.55"
  ragReconcileHour: "4"
  ragReconcileMinute: "15"
  ragTombstoneRetentionDays: "30"
  ragAssistanceRetentionDays: "90"
  ragRetentionHour: "4"
  ragRetentionMinute: "45"
```

`localLlmBaseUrl` must resolve to loopback/private/link-local addressing or a
recognized private service DNS name. A public hostname cannot be relabeled as
the local provider. Add deployment-specific NetworkPolicy/mesh egress rules,
authentication, TLS, request logging, and retention controls for the model
Service. Store `LOCAL_LLM_API_KEY` in the runtime Secret, not in values.

Confirm the embedding model returns exactly `ragEmbeddingDimensions` values
before activation. The value defines the PostgreSQL vector column; changing it
later requires a reviewed schema migration and complete reindex. Disable
embeddings during initial deployment if the model has not passed that test.

The worker and Beat deployments receive the same RAG schedule and retention
configuration through the ConfigMap. The base chart connects the worker
directly to bundled PostgreSQL, which satisfies the reconciliation session-lock
requirement. A custom external-database overlay must use a direct connection or
PgBouncer `pool_mode=session`; transaction and statement pooling are
unsupported for this worker path.

After rollout, sign in with a `manage_feeds` account and open **ATT&CK Navigator
→ AI RAG assistant → Build / refresh RAG index**. Wait for the run to
complete and verify corpus/source counts, pending/failed embeddings, and the
latest indexed time before accepting the feature. Then run exact IOC/CVE/ATT&CK
queries, an approved non-sensitive semantic query, and a citation/temporary
Navigator proposal review.

The Helm chart does not deploy the optional MCP process. Run MCP as a local
stdio subprocess of the approved client and connect it to the authenticated
HTTPS ingress with a dedicated least-privilege analyst session. Do not add an
MCP HTTP/SSE listener to the chart. See
[`docs/mcp-server.md`](../../docs/mcp-server.md).

## Production Boundaries

- Configure TLS and an explicit `config.corsAllowedOrigins`; never use `*` with
  credentials.
- Keep `config.secureCookies: "true"` for HTTPS deployments.
- Create permanent named administrators, then remove
  `AUTH_BOOTSTRAP_ADMIN_PASSWORD` from the Secret and restart the API.
- Run backup and restore drills before storing private investigation data.
- Include RAG documents/chunks/embeddings, business profiles, assistance,
  proposals, and any MCP-client copies in classification, retention, backup,
  deletion, and incident-response policy.
- Monitor the RAG index status and run history; an enabled empty corpus, stale
  run heartbeat, or failed embedding population is not semantic-search
  readiness.
- Review resource sizing in
  [`docs/deployment-sizing.md`](../../docs/deployment-sizing.md).
- Review and extend the chart's baseline ingress NetworkPolicies; supply
  deployment-specific egress/DNS policy, Pod Security admission, image-signing
  policy, monitoring, backup automation, and secret rotation.
- The chart has no Alembic migration Job; v6 still uses additive startup schema
  compatibility, so upgrades require a verified logical backup.
- The chart does not deploy the attack-lab web or endpoint fixtures. Keep those
  fixtures in a separate authorized lab environment.
- MalwareGraph dynamic/runtime behavior remains disabled unless an operator
  explicitly approves an isolated disposable runtime.

See [`SECURITY.md`](../../SECURITY.md),
[`docs/release-readiness-v6.md`](../../docs/release-readiness-v6.md), and
[`docs/backup-restore.md`](../../docs/backup-restore.md).

## Scanner findings that require deployment context

Generic manifest scanners cannot infer every Helm or image contract. The
following findings are not suppressed in the templates and must be handled in
the deployment review:

- `CKV_K8S_21`: namespaced resources deliberately omit
  `metadata.namespace`, which is standard for reusable Helm charts. Install
  with `--namespace adversarygraph --create-namespace` as shown above and scan
  the release in that namespace. Do not hard-code a namespace into the chart.
- `CKV_K8S_35`: AdversaryGraph and the upstream PostgreSQL/Redis images consume
  credentials through environment variables. The chart references an
  externally managed Secret and does not place secret values in ConfigMaps or
  rendered default values. Converting to secret files requires application and
  upstream entrypoint support; protect Secret RBAC, admission, audit, and
  rotation instead of applying an incompatible manifest-only rewrite.
- `CKV_K8S_40`: API/worker/beat, frontend, PostgreSQL, and Redis use the
  non-root UIDs defined and tested by their images. Raising those UIDs solely
  for a scanner can break image files and persistent-volume ownership. The
  chart enforces `runAsNonRoot`, drops all capabilities, disables privilege
  escalation and service-account token mounting, and uses the compatible UID.
- `CKV_K8S_43`: the three tag-based custom images remain findings in a default
  render until the operator supplies the release's reviewed digests.
  Redis and the development pgvector compatibility image are digest-pinned.
  Production must replace the compatibility image and set reviewed
  revision-matched digests for PostgreSQL and all custom images. The chart
  validates digest syntax but cannot invent registry digests for unpublished
  custom artifacts.

The chart directly addresses `CKV2_K8S_6` with baseline NetworkPolicies,
`CKV_K8S_15` with an `Always` pull policy, and `CKV_K8S_22` for PostgreSQL by
using a read-only root filesystem plus writable data, socket, and temporary
mounts.
