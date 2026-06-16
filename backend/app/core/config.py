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
    openai_model: str = "gpt-4.1"
    gemini_api_key: str = ""
    local_llm_base_url: str = "http://host.docker.internal:11434/v1"
    local_llm_api_key: str = "local"
    local_llm_model: str = "llama3.1:8b"

    # ATT&CK ingestion
    attck_domains: str = "enterprise-attack,mobile-attack,ics-attack"
    attck_data_dir: str = "/app/data/attck"

    # Optional trusted-proxy team authentication. Keep disabled for local use.
    auth_enabled: bool = False
    auth_default_role: str = "admin"

    log_level: str = "info"

    @property
    def attck_domain_list(self) -> list[str]:
        return [d.strip() for d in self.attck_domains.split(",") if d.strip()]

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
