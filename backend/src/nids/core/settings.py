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


@lru_cache
def get_settings() -> Settings:
    return Settings()
