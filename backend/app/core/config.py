from pydantic_settings import BaseSettings
from functools import lru_cache
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    # Database
    database_url: str = ""
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "threatmapper"
    db_user: str = "tm_user"
    db_pass: str = "changeme"

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
    attck_domains: str = "enterprise-attack,mobile-attack,ics-attack,atlas"
    attck_data_dir: str = "/app/data/attck"

    # IOC intelligence feeds
    threatfox_auth_key: str = ""
    otx_api_key: str = ""

    # Optional trusted-proxy team authentication. Keep disabled for local use.
    auth_enabled: bool = False
    auth_default_role: str = "admin"

    log_level: str = "info"

    @property
    def attck_domain_list(self) -> list[str]:
        return [d.strip() for d in self.attck_domains.split(",") if d.strip()]

    @property
    def sqlalchemy_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return URL.create(
            "postgresql+asyncpg",
            username=self.db_user,
            password=self.db_pass,
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        ).render_as_string(hide_password=False)

    @property
    def sync_database_url(self) -> str:
        return self.sqlalchemy_database_url.replace("+asyncpg", "+psycopg2")

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
