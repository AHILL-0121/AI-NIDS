"""Application settings.

A single source of truth, with precedence CLI > environment (``NIDS_*``) > ``.env`` > defaults
(audit API-09). Only fields declared here exist; unknown keys are rejected (audit SEC-02).
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NIDS_",
        env_file=".env",
        extra="forbid",
    )

    # Loopback by default; exposing the API on the LAN is an explicit opt-in (audit SEC-01).
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1024, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Storage (Phase 4)
    database_url: str = "sqlite:///data/nids.db"
    flow_sample_rate: float = Field(default=1.0, ge=0.0, le=1.0)  # share of flows stored
    retention_flows_days: float = Field(default=7, gt=0)
    retention_alerts_days: float = Field(default=90, gt=0)
    retention_traffic_1s_hours: float = Field(default=24, gt=0)
    retention_traffic_1m_days: float = Field(default=90, gt=0)
    pseudonymize_ips: bool = False  # store IP addresses as keyed hashes (audit SEC-11)

    # API (Phase 5)
    data_dir: str = "data"  # uploads/, jobs/, logs/ live here
    artifacts_dir: str = "artifacts"
    frontend_dir: str = "../frontend/out"  # the Next.js static export, served when present
    session_ttl_hours: float = Field(default=12, gt=0, le=24 * 30)
    secure_cookies: bool = False  # set True when served over HTTPS
    allowed_origins: list[str] = []  # extra browser origins for the WebSocket (dev servers)
    upload_max_mb: int = Field(default=512, gt=0, le=10_240)
    max_concurrent_jobs: int = Field(default=2, ge=1, le=8)

    # Reports (Phase 8): PDFs are printed by a headless Chromium-based browser (Edge, Chrome,
    # Chromium). Found automatically when unset; without one, reports are HTML only.
    pdf_browser: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
