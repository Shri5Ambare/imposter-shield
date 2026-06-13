"""Central configuration. All secrets come from the environment, never code.

Defaults are dev-friendly (SQLite, ephemeral key) so the app runs with zero
setup. In production (`ISHLD_ENVIRONMENT=production`) the app refuses to start
with an ephemeral key or wildcard hosts — fail closed, not open.
"""
from __future__ import annotations

import os
import secrets

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ISHLD_", extra="ignore")

    # --- deployment --------------------------------------------------------
    environment: str = "dev"            # "dev" | "production"

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
    # Stored as comma-separated strings (ergonomic for env config and robust
    # across pydantic-settings versions); read via the *_list properties below.
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    allowed_hosts: str = "localhost,127.0.0.1,testserver"
    rate_limit_default: str = "120/minute"
    rate_limit_auth: str = "10/minute"      # brute-force resistance on login
    rate_limit_write: str = "30/minute"     # mutating/expensive endpoints

    # SSRF: by default suspect/evidence URLs and worker image fetches may not
    # resolve to private/loopback/link-local addresses. Flip only for testing.
    allow_private_network_urls: bool = False

    # Reverse-proxy trust depth for rate-limit / audit IP extraction.
    # 0 = no proxy (use request.client.host directly).
    # 1 = one trusted proxy (e.g. nginx); reads the leftmost X-Forwarded-For value.
    # Only set > 0 if you have a trusted reverse proxy that sets X-Forwarded-For.
    trusted_proxy_depth: int = 0

    # --- image ingestion limits (worker) -----------------------------------
    image_max_bytes: int = 25 * 1024 * 1024     # 25 MB hard cap per download
    image_download_timeout: int = 15            # seconds per image

    # --- external services (optional) -------------------------------------
    serpapi_key: str | None = None
    vt_api_key: str | None = None

    # --- scoring policy (tunable without code change) ----------------------
    review_threshold: float = 0.90
    score_weight_face: float = 0.45
    score_weight_text: float = 0.20
    score_weight_heuristics: float = 0.35
    watermark_boost: float = 0.40

    # --- evidence ----------------------------------------------------------
    out_dir: str = "./out"
    dossier_retention_days: int = 30        # older PDFs are pruned on generate

    @staticmethod
    def _csv(value: str) -> list[str]:
        return [item.strip() for item in value.split(",") if item.strip()]

    @property
    def cors_origins_list(self) -> list[str]:
        return self._csv(self.cors_origins)

    @property
    def allowed_hosts_list(self) -> list[str]:
        return self._csv(self.allowed_hosts)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


def _load() -> Settings:
    s = Settings()
    s.secret_key_is_ephemeral = "ISHLD_SECRET_KEY" not in os.environ

    if s.is_production:
        problems = []
        if s.secret_key_is_ephemeral:
            problems.append("ISHLD_SECRET_KEY must be set in production")
        if "*" in s.allowed_hosts_list:
            problems.append("ISHLD_ALLOWED_HOSTS must not be a wildcard in production")
        if any(o.startswith("http://") and "localhost" not in o and "127.0.0.1" not in o
               for o in s.cors_origins_list):
            problems.append("CORS origins should be https:// in production")
        if problems:
            raise RuntimeError(
                "Refusing to start in production with insecure config:\n  - "
                + "\n  - ".join(problems)
            )
    return s


settings = _load()
