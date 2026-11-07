from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = "development"
    app_name: str = "Provenance Cloud"

    # Oracle
    db_dsn: str = "localhost:1521/orclpdb"
    db_app_user: str = "PROV_APP"
    db_app_password: str = ""
    db_owner_user: str = "PROV_OWNER"
    db_owner_password: str = ""
    db_schema: str = "PROV_OWNER"
    db_pool_min: int = 2
    db_pool_max: int = 10

    # Bootstrap (scripts/setup_db.py only)
    oracle_sid: str = "ORCL"
    oracle_pdb: str = "ORCLPDB"
    sqlplus_path: str = r"C:\oracle_db\bin\sqlplus.exe"

    # Auth
    jwt_secret: str = Field(default="", min_length=0)
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    refresh_token_days: int = 7

    # HTTP
    cors_origins: list[str] = []
    login_rate_limit_per_minute: int = 10
    api_key_rate_limit_per_minute: int = 600  # per API key; a batch call counts once
    redis_url: str = ""  # e.g. redis://localhost:6379/0; shared rate limits across processes

    # Background workers
    workers_enabled: bool = True
    dispatcher_interval_seconds: float = 2.0
    rules_interval_seconds: float = 60.0
    webhook_timeout_seconds: float = 5.0
    webhook_max_attempts: int = 5
    webhook_allow_private_urls: bool = True  # must be False in production (SSRF)

    @property
    def is_dev(self) -> bool:
        return self.environment.lower() in {"development", "dev", "local", "test"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
