from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings
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
    gemini_model: str = "gemini-3.5-flash"
    minimax_api_key: str = ""
    minimax_model: str = "MiniMax-M3"
    minimax_base_url: str = "https://api.minimax.io/v1"
    local_llm_base_url: str = "http://host.docker.internal:11434/v1"
    local_llm_api_key: str = "local"
    local_llm_model: str = "llama3.1:8b"

    # Threat Hunting AI is an advisory-only feature. Cloud processing remains
    # disabled until an operator explicitly enables it and the analyst confirms
    # the data-processing boundary for each request.
    threat_hunting_ai_enabled: bool = True
    threat_hunting_ai_cloud_enabled: bool = False
    threat_hunting_ai_default_provider: str = "local"
    threat_hunting_ai_timeout_seconds: float = 45.0
    threat_hunting_ai_source_char_limit: int = 40_000
    threat_hunting_ai_max_candidates: int = 3

    # Unified intelligence RAG. Embeddings use the same private
    # OpenAI-compatible boundary as the local LLM by default, but a distinct
    # model because chat models are not valid embedding models.
    rag_enabled: bool = True
    rag_embedding_enabled: bool = False
    rag_embedding_provider: Literal["local"] = "local"
    rag_embedding_model: str = "nomic-embed-text"
    rag_embedding_dimensions: int = Field(default=768, ge=1, le=2_000)
    rag_embedding_batch_size: int = Field(default=32, ge=1, le=128)
    # Cosine distance is 0 for identical vectors and approaches 2 for opposite
    # vectors. Reject weak semantic neighbours before reciprocal-rank fusion.
    rag_vector_max_cosine_distance: float = Field(default=0.55, ge=0.0, le=2.0)
    rag_chunk_chars: int = Field(default=3_500, ge=500, le=10_000)
    rag_chunk_overlap_chars: int = Field(default=350, ge=0, le=2_000)
    rag_default_result_limit: int = Field(default=12, ge=1, le=25)
    rag_max_context_chars: int = Field(default=32_000, ge=4_000, le=80_000)
    rag_reconcile_hour: int = Field(default=4, ge=0, le=23)
    rag_reconcile_minute: int = Field(default=15, ge=0, le=59)
    # Derived RAG data has an explicit, bounded lifecycle. A zero retention
    # value disables automatic deletion for that record family (legal-hold
    # mode); backups and manual administrative deletion remain separate.
    rag_tombstone_retention_days: int = Field(default=30, ge=0, le=36_500)
    rag_assistance_retention_days: int = Field(default=90, ge=0, le=36_500)
    rag_retention_batch_size: int = Field(default=1_000, ge=1, le=10_000)
    rag_retention_max_batches: int = Field(default=20, ge=1, le=100)
    rag_retention_hour: int = Field(default=4, ge=0, le=23)
    rag_retention_minute: int = Field(default=45, ge=0, le=59)

    # MCP is a separate, local stdio process. Remote HTTP transport is not
    # exposed until the platform has an independent OAuth authorization model.
    mcp_transport: Literal["stdio"] = "stdio"
    # MCP is normally launched as a host-side stdio subprocess. The standard
    # Compose deployment exposes the authenticated API through the frontend
    # proxy on loopback port 3000; in-container deployments must override this
    # with http://api:8000 explicitly.
    mcp_api_base_url: str = "http://127.0.0.1:3000"
    mcp_api_token: str = ""

    # MalwareGraph integration
    malwaregraph_url: str = "http://malwaregraph:8100"
    malwaregraph_api_key: str = ""
    malwaregraph_request_timeout_seconds: int = 30
    malwaregraph_upload_timeout_seconds: int = 180
    malwaregraph_long_timeout_seconds: int = 300
    malwaregraph_max_upload_bytes: int = 256 * 1024 * 1024
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

    # RetroHunt collectors
    nvd_api_key: str = ""          # Optional — increases NVD rate limit from 5 to 50 req/30s
    github_token: str = ""         # Optional — increases GitHub API rate limit
    gitlab_token: str = ""         # Optional — GitLab advisory and code/security searches
    msrc_api_key: str = ""         # Optional — Microsoft Security Update Guide higher limits
    deps_dev_api_key: str = ""     # Optional — deps.dev package/dependency API
    vulncheck_api_key: str = ""    # Optional — VulnCheck KEV, NVD++, exploit intelligence
    snyk_token: str = ""           # Optional — Snyk vulnerability/package intelligence
    socket_token: str = ""         # Optional — Socket package supply-chain risk intelligence
    endoflife_date_token: str = "" # Optional — endoflife.date commercial API, if used
    hibp_api_key: str = ""         # Optional — Have I Been Pwned domain breach monitoring
    leakix_api_key: str = ""       # Optional — LeakIX exposure monitoring
    spycloud_api_key: str = ""     # Optional — SpyCloud breach/credential exposure
    flare_api_key: str = ""        # Optional — Flare dark web and leaked credential monitoring
    darkowl_api_key: str = ""      # Optional — DarkOwl darknet intelligence
    intel471_api_key: str = ""     # Optional — Intel 471 adversary/darknet reporting
    kela_api_key: str = ""         # Optional — KELA cybercrime intelligence
    recorded_future_api_key: str = "" # Optional — Recorded Future vulnerability/threat intelligence

    # OpenCTI symmetric sync
    opencti_url: str = ""
    opencti_token: str = ""
    opencti_sync_limit: int = 500
    opencti_verify_tls: bool = True

    # Optional trusted-proxy team authentication. Keep disabled for local use.
    auth_enabled: bool = False
    auth_sso_mode: str = "proxy"  # proxy, oidc-proxy, saml-proxy
    auth_default_role: str = "viewer"
    auth_session_minutes: int = 720
    auth_password_min_length: int = 12
    auth_password_require_upper: bool = False
    auth_password_require_lower: bool = False
    auth_password_require_number: bool = False
    auth_password_require_special: bool = False
    auth_mfa_enabled: bool = False
    auth_bootstrap_admin_username: str = "admin"
    auth_bootstrap_admin_password: str = ""
    # Secret shared between the reverse proxy and the API. When non-empty, every
    # request that carries X-Auth-User / X-Auth-Roles headers MUST also carry
    # X-Internal-Proxy-Secret with this value; requests that fail the check are
    # treated as anonymous regardless of AUTH_ENABLED.
    proxy_secret: str = ""
    # Separate secret used only by the bundled reverse proxy to authenticate
    # X-Forwarded-For for rate-limit client attribution.  Do not reuse the
    # trusted-identity proxy secret above: these headers have different trust
    # boundaries and are consumed for different security decisions.
    rate_limit_proxy_secret: str = ""
    # Set to false when running behind an HTTP-only reverse proxy in local dev.
    # Must be true in production deployments served over HTTPS.
    secure_cookies: bool = True

    # CORS — comma-separated list of allowed origins.
    # In production set this to the actual frontend domain, e.g.
    #   CORS_ALLOWED_ORIGINS=https://adversarygraph.example.com
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:5173"

    log_level: str = "info"
    log_dir: str = "logs"
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5

    @model_validator(mode="after")
    def validate_rag_settings(self):
        if self.rag_chunk_overlap_chars >= self.rag_chunk_chars:
            raise ValueError("RAG_CHUNK_OVERLAP_CHARS must be smaller than RAG_CHUNK_CHARS")
        return self

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
