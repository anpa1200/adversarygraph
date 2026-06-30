# AdversaryGraph Helm Chart

This chart is a production-readiness scaffold for Kubernetes deployments. It is
intended for controlled internal environments and should be reviewed before
internet exposure.

## Render

```bash
helm template adversarygraph ./helm/adversarygraph \
  --set secrets.dbPassword="$(openssl rand -hex 32)" \
  --set secrets.redisPassword="$(openssl rand -hex 32)" \
  --set secrets.authBootstrapAdminPassword="$(openssl rand -hex 24)"
```

## Install

```bash
kubectl create namespace adversarygraph
helm install adversarygraph ./helm/adversarygraph -n adversarygraph -f values.prod.yaml
```

## Production Notes

- Prefer `secrets.existingSecret` with externally managed Kubernetes Secrets.
- Use managed PostgreSQL and Redis for production if available.
- Configure TLS through ingress.
- Review resource requests/limits using `docs/deployment-sizing.md`.
- Run backup/restore drills before using private investigation data.
- This chart does not yet include Alembic migration jobs because the current app
  still uses additive startup schema creation.
