.PHONY: up pull prod prod-preflight down build logs shell-api shell-db ingest reset sync-atlas sync-atlas-release security-scan security-scan-strict backup local-ai-start local-ai-pull local-ai-up

LOCAL_AI_COMPOSE = docker compose -f docker-compose.yml -f docker-compose.local-ai.yml

up:
	docker compose up --build

pull:
	docker compose pull

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
	@echo "Automatic reset is disabled: PostgreSQL lives in ADVERSARYGRAPH_DB_DIR, not a Docker volume."
	@echo "Use the reversible move-aside procedure in docs/quickstart.md#troubleshooting-postgresql-password-mismatch."
	@exit 2

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

local-ai-start:
	$(LOCAL_AI_COMPOSE) up -d ollama

local-ai-pull: local-ai-start
	$(LOCAL_AI_COMPOSE) exec -T ollama sh -ec 'ollama pull "$$LOCAL_LLM_MODEL"'

local-ai-up: local-ai-pull
	$(LOCAL_AI_COMPOSE) up -d --build api worker frontend
