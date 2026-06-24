from pydantic_settings import BaseSettings
from functools import lru_cache
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    # Database
    database_url: str = ""
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "adversarygraph"
    db_user: str = "ag_user"
    db_pass: str

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"

    # AI providers
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    openai_model: str = "gpt-4.1"
    gemini_api_key: str = ""
    minimax_api_key: str = ""
    minimax_model: str = "MiniMax-M3"
    minimax_base_url: str = "https://api.minimax.io/v1"
    local_llm_base_url: str = "http://host.docker.internal:11434/v1"
    local_llm_api_key: str = "local"
    local_llm_model: str = "llama3.1:8b"

    # MalwareGraph integration
    malwaregraph_url: str = "http://malwaregraph:8100"
    malwaregraph_api_key: str = ""
    malwaregraph_request_timeout_seconds: int = 30
    malwaregraph_upload_timeout_seconds: int = 180
    malwaregraph_long_timeout_seconds: int = 300
    malwaregraph_storage_dir: str = "/malwaregraph-storage"

    # ATT&CK ingestion
    attck_domains: str = "enterprise-attack,mobile-attack,ics-attack,atlas"
    attck_data_dir: str = "/app/data/attck"

    # IOC intelligence feeds
    threatfox_auth_key: str = ""
    auto_ioc_full_sync_on_startup: bool = True
    auto_threatfox_sync_days: int = 7
    dynamic_db_sync_hour: int = 3
    dynamic_db_sync_minute: int = 30
    dynamic_db_ioc_sync_days: int = 7
    otx_api_key: str = ""
    otx_connect_timeout_seconds: int = 10
    otx_read_timeout_seconds: int = 90
    otx_retries: int = 2
    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    greynoise_api_key: str = ""
    shodan_api_key: str = ""
    abuseipdb_api_key: str = ""
    censys_api_key: str = ""
    censys_org_id: str = ""

    # OpenCTI symmetric sync
    opencti_url: str = ""
    opencti_token: str = ""
    opencti_sync_limit: int = 500
    opencti_verify_tls: bool = True

    # Optional trusted-proxy team authentication. Keep disabled for local use.
    auth_enabled: bool = False
    auth_default_role: str = "viewer"
    # Secret shared between the reverse proxy and the API. When non-empty, every
    # request that carries X-Auth-User / X-Auth-Roles headers MUST also carry
    # X-Internal-Proxy-Secret with this value; requests that fail the check are
    # treated as anonymous regardless of AUTH_ENABLED.
    proxy_secret: str = ""

    # CORS — comma-separated list of allowed origins.
    # In production set this to the actual frontend domain, e.g.
    #   CORS_ALLOWED_ORIGINS=https://adversarygraph.example.com
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:5173"

    log_level: str = "info"
    log_dir: str = "logs"
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5

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
