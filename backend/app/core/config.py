from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://tm_user:changeme@localhost:5432/threatmapper"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"

    # AI providers
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    gemini_api_key: str = ""

    # ATT&CK ingestion
    attck_domains: str = "enterprise-attack,mobile-attack,ics-attack"
    attck_data_dir: str = "/app/data/attck"

    log_level: str = "info"

    @property
    def attck_domain_list(self) -> list[str]:
        return [d.strip() for d in self.attck_domains.split(",") if d.strip()]

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
