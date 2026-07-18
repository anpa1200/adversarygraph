.PHONY: up prod prod-preflight down build logs shell-api shell-db ingest reset sync-atlas sync-atlas-release security-scan security-scan-strict backup

up:
	docker compose up

prod:
	./scripts/validate-production-env.sh
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-build

prod-preflight:
	./scripts/validate-production-env.sh

build:
	docker compose build --no-cache

down:
	docker compose down

logs:
	docker compose logs -f api worker

shell-api:
	docker compose exec api bash

shell-db:
	docker compose exec postgres sh -lc 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

ingest:
	docker compose exec api python -c "import asyncio; from app.services.attck.ingestor import run_ingest; asyncio.run(run_ingest())"

reset:
	docker compose down -v
	docker compose up --build

sync-atlas:
	./scripts/sync-anomaly-atlas.sh

sync-atlas-release:
	ATLAS_PREFER_LOCAL_SOURCE=false ./scripts/sync-anomaly-atlas.sh

security-scan:
	./scripts/security-scan.sh --best-effort

security-scan-strict:
	./scripts/security-scan.sh --strict

backup:
	./scripts/backup.sh
