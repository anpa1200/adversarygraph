.PHONY: up down build logs shell-api shell-db ingest reset sync-atlas

up:
	docker compose up

build:
	docker compose build --no-cache

down:
	docker compose down

logs:
	docker compose logs -f api worker

shell-api:
	docker compose exec api bash

shell-db:
	docker compose exec postgres psql -U tm_user -d threatmapper

ingest:
	docker compose exec api python -c "import asyncio; from app.services.attck.ingestor import run_ingest; asyncio.run(run_ingest())"

reset:
	docker compose down -v
	docker compose up --build

sync-atlas:
	./scripts/sync-anomaly-atlas.sh
