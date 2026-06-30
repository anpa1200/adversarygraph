.PHONY: up prod down build logs shell-api shell-db ingest reset sync-atlas security-scan backup

up:
	docker compose up

prod:
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

build:
	docker compose build --no-cache

down:
	docker compose down

logs:
	docker compose logs -f api worker

shell-api:
	docker compose exec api bash

shell-db:
	docker compose exec postgres psql -U ag_user -d adversarygraph

ingest:
	docker compose exec api python -c "import asyncio; from app.services.attck.ingestor import run_ingest; asyncio.run(run_ingest())"

reset:
	docker compose down -v
	docker compose up --build

sync-atlas:
	./scripts/sync-anomaly-atlas.sh

security-scan:
	./scripts/security-scan.sh

backup:
	./scripts/backup.sh
