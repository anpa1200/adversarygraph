# AdversaryGraph Helm Chart

This chart is a deployment scaffold for a controlled, single-workspace
Kubernetes installation. The checked-out `main` chart contains post-v6 controls
and must not be represented as the chart from the immutable `v6.0.0` tag. It
requires a new successfully gated semantic release and its image manifest
before production use. It is not a managed-SaaS or multi-tenant isolation
boundary.

## Prerequisites

- Kubernetes 1.27 or newer
- Helm 3
- a default StorageClass, or explicit storage classes for every PVC
- an ingress controller and certificate workflow when TLS ingress is enabled
- an externally managed Secret for any production-like installation

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

The backend, frontend, and MalwareGraph images default to versioned tags with
`imagePullPolicy: Always`. The chart-evaluation defaults for upstream
PostgreSQL and Redis are digest-pinned. The PostgreSQL compatibility image is
not the remediated release image and does not satisfy the strict post-v6 stack
gate. For production, use the release manifest to replace it with the custom
`adversarygraph-postgres` repository and set reviewed digests for all four
release images; a configured digest takes precedence over its human-readable
tag:

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

## Production Boundaries

- Configure TLS and an explicit `config.corsAllowedOrigins`; never use `*` with
  credentials.
- Keep `config.secureCookies: "true"` for HTTPS deployments.
- Create permanent named administrators, then remove
  `AUTH_BOOTSTRAP_ADMIN_PASSWORD` from the Secret and restart the API.
- Run backup and restore drills before storing private investigation data.
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
  PostgreSQL and Redis compatibility defaults are digest-pinned, but production
  must also replace the PostgreSQL repository/digest with the remediated release
  artifact. The chart validates digest syntax but cannot invent registry
  digests for unpublished custom artifacts.

The chart directly addresses `CKV2_K8S_6` with baseline NetworkPolicies,
`CKV_K8S_15` with an `Always` pull policy, and `CKV_K8S_22` for PostgreSQL by
using a read-only root filesystem plus writable data, socket, and temporary
mounts.
