"""Central configuration. All secrets come from the environment, never code.

Defaults are dev-friendly (SQLite, ephemeral key) so the app runs with zero
setup. The startup banner warns loudly when you're running with an ephemeral
secret so it never silently ships to production.
"""
from __future__ import annotations

import secrets

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ISHLD_", extra="ignore")

    # --- auth / crypto -----------------------------------------------------
    # If unset, a random key is generated per-process. That invalidates tokens
    # on restart and is NOT safe for multi-process prod — set ISHLD_SECRET_KEY.
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    secret_key_is_ephemeral: bool = True
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # --- storage -----------------------------------------------------------
    database_url: str = "sqlite:///./imposter_shield.db"

    # --- network hardening -------------------------------------------------
    cors_origins: list[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "testserver"]
    rate_limit_default: str = "120/minute"
    rate_limit_auth: str = "10/minute"      # brute-force resistance on login

    # --- external services (optional) -------------------------------------
    serpapi_key: str | None = None
    vt_api_key: str | None = None

    # --- policy ------------------------------------------------------------
    review_threshold: float = 0.90
    out_dir: str = "./out"


def _load() -> Settings:
    import os
    s = Settings()
    # Record whether the operator actually supplied a key.
    s.secret_key_is_ephemeral = "ISHLD_SECRET_KEY" not in os.environ
    return s


settings = _load()
