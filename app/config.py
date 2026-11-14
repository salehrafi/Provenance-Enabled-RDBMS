"""Environment-based configuration.

Every setting comes from the environment (or a local .env file in development). There are no
default secrets: `python -m app.cli init` generates them for a developer machine, and a
deployment must supply its own. `Settings.problems()` lists anything that makes the current
configuration unsafe; the application refuses to start in production while that list is non-empty.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parent.parent


def _b64_len(value: str) -> int:
    try:
        return len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
    except Exception:
        return -1


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = "development"
    app_name: str = "Provenance Cloud"
    log_level: str = "INFO"
    docs_enabled: bool = True  # /docs, /redoc (the OpenAPI JSON itself is always served)

    # --- PostgreSQL -------------------------------------------------------------------------
    # Runtime connection (role prov_app: no superuser, no BYPASSRLS).
    database_url: str = ""
    # Migrations only (role prov_owner). Not needed by the running API or worker.
    database_owner_url: str = ""
    # Bootstrap only (a superuser, to create the two roles and the database).
    database_admin_url: str = ""
    # Platform console (global administration). Role prov_platform: no access to tenant tables at all.
    # Leave unset to disable the platform console entirely.
    database_platform_url: str = ""
    db_pool_min: int = 2
    db_pool_max: int = 10
    db_pool_timeout_seconds: float = 10.0
    # After a database outage the pool retries with backoff; a short attempt window restarts the backoff
    # so service resumes within seconds of the database coming back (psycopg's default is 300 s).
    db_reconnect_timeout_seconds: float = 15.0
    db_statement_timeout_ms: int = 15_000
    db_lock_timeout_ms: int = 10_000
    db_idle_in_transaction_timeout_ms: int = 60_000
    # Set to false behind PgBouncer in transaction-pooling mode (server-side prepared
    # statements do not survive there).
    db_prepared_statements: bool = True

    # --- Secrets ----------------------------------------------------------------------------
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 15
    refresh_token_days: int = 14
    # 32 random bytes, base64url. Encrypts webhook signing secrets at rest (AES-256-GCM).
    data_encryption_key: str = ""
    # Ed25519 private key seed (32 bytes, base64url). Signs audit-chain checkpoints.
    checkpoint_signing_key: str = ""

    # --- HTTP -------------------------------------------------------------------------------
    cors_origins: list[str] = []
    # The refresh cookie is marked Secure unless this is explicitly disabled for local http.
    cookie_secure: bool = True
    login_rate_limit_per_minute: int = 10
    api_key_rate_limit_per_minute: int = 600
    user_rate_limit_per_minute: int = 600
    redis_url: str = ""
    max_request_bytes: int = 6 * 1024 * 1024
    # Record every authenticated read in the activity log, not only changes and sensitive reads.
    activity_log_reads: bool = False

    # --- Platform administration and break-glass ---------------------------------------------
    platform_token_minutes: int = 30
    platform_mfa_fresh_minutes: int = 5     # sensitive platform actions need a TOTP check this recent
    platform_mfa_issuer: str = "Provenance Cloud"
    # Independent, append-only store for platform checkpoints (put it on WORM storage; see SECURITY.md).
    platform_anchor_path: str = ""
    platform_checkpoint_interval_seconds: float = 300.0

    # --- Background work --------------------------------------------------------------------
    # Run the worker loop inside the API process. Convenient on a laptop; in production run
    # `python -m app.worker` as its own service and leave this off.
    workers_enabled: bool = False
    dispatcher_interval_seconds: float = 2.0
    rules_interval_seconds: float = 60.0
    checkpoint_interval_seconds: float = 300.0
    # Full re-verification of every organization's whole chain. Checkpoints are only signed after it passes.
    full_verify_interval_seconds: float = 3600.0
    prune_interval_seconds: float = 3600.0
    delivery_retention_days: int = 30
    # Optional append-only file that receives every checkpoint (one JSON object per line).
    # Point it at storage the database administrators cannot write to.
    checkpoint_anchor_path: str = ""

    # --- Webhooks ---------------------------------------------------------------------------
    webhook_timeout_seconds: float = 5.0
    webhook_max_attempts: int = 12
    webhook_lease_seconds: int = 60
    webhook_allow_private_urls: bool = False  # true only for local development (SSRF)
    webhook_allow_http: bool = False          # plain http is refused unless enabled

    # --- Demo data --------------------------------------------------------------------------
    demo_password: str = ""

    @property
    def is_dev(self) -> bool:
        return self.environment.lower() in {"development", "dev", "local", "test"}

    def problems(self) -> list[str]:
        """Configuration errors. Any entry stops startup outside development."""
        out: list[str] = []
        if not self.database_url:
            out.append("DATABASE_URL is not set")
        if len(self.jwt_secret) < 32:
            out.append("JWT_SECRET must be at least 32 characters")
        if _b64_len(self.data_encryption_key) != 32:
            out.append("DATA_ENCRYPTION_KEY must be 32 random bytes, base64url encoded")
        if _b64_len(self.checkpoint_signing_key) != 32:
            out.append("CHECKPOINT_SIGNING_KEY must be a 32-byte Ed25519 seed, base64url encoded")
        if not self.is_dev:
            if self.webhook_allow_private_urls:
                out.append("WEBHOOK_ALLOW_PRIVATE_URLS must be false outside development (SSRF)")
            if self.webhook_allow_http:
                out.append("WEBHOOK_ALLOW_HTTP must be false outside development")
            if not self.cookie_secure:
                out.append("COOKIE_SECURE must be true outside development")
            if "*" in self.cors_origins:
                out.append("CORS_ORIGINS must list explicit origins, not '*'")
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
