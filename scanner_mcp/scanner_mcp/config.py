from __future__ import annotations

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


class ScannerSettings(BaseSettings):
    """Configuration owned only by the isolated scanner container."""

    # Container-only listener; Compose/Helm do not publish this port and enforce
    # API-pod-only ingress.
    scanner_mcp_host: str = "0.0.0.0"  # nosec B104
    scanner_mcp_port: int = Field(default=8200, ge=1, le=65_535)
    scanner_mcp_token: str = Field(min_length=24, max_length=4_096)
    scanner_mcp_public_url: str = "http://scanner-mcp:8200"

    nmap_enabled: bool = True
    web_probe_enabled: bool = True
    tls_enabled: bool = True
    dns_enabled: bool = True
    nuclei_enabled: bool = True

    nmap_binary: str = "/usr/bin/nmap"
    nuclei_binary: str = "/usr/local/bin/nuclei"
    nuclei_templates: str = "/app/nuclei-templates"

    nmap_timeout_seconds: int = Field(default=120, ge=15, le=600)
    web_probe_timeout_seconds: int = Field(default=15, ge=5, le=60)
    tls_timeout_seconds: int = Field(default=15, ge=5, le=60)
    dns_timeout_seconds: int = Field(default=10, ge=3, le=60)
    nuclei_timeout_seconds: int = Field(default=180, ge=30, le=900)
    nuclei_rate_limit: int = Field(default=25, ge=1, le=50)
    nuclei_concurrency: int = Field(default=5, ge=1, le=10)
    nmap_top_ports: int = Field(default=100, ge=10, le=1_000)
    max_resolved_ips: int = Field(default=4, ge=1, le=16)
    max_output_bytes: int = Field(
        default=5 * 1024 * 1024, ge=64 * 1024, le=20 * 1024 * 1024
    )

    @model_validator(mode="after")
    def validate_service_token(self):
        if self.scanner_mcp_token in {
            "development-only-scanner-mcp-token",
            "change-me-scanner-mcp-token",
        }:
            # The source Compose stack may use the documented development value.
            # Production preflight rejects it before deployment.
            return self
        if len(set(self.scanner_mcp_token)) < 8:
            raise ValueError(
                "SCANNER_MCP_TOKEN does not have enough character diversity"
            )
        return self

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = ScannerSettings()
