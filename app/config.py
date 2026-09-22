from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ScamShield AI"
    app_env: str = "production"
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 8080

    rate_limit_checks_per_minute: int = 12
    rate_limit_uploads_per_minute: int = 6
    max_text_chars: int = 20_000
    max_upload_bytes: int = 4_000_000

    data_dir: Path = Path("./data")
    audit_retain_days: int = 30
    store_raw_content: bool = False

    google_safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""
    intel_timeout_seconds: float = 3.5

    household_hash_salt: str = "change-me-in-production"
    cors_origins: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        if not self.cors_origins.strip():
            return []
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
