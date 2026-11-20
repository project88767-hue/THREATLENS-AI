from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    port: int = 8088
    environment: str = "development"
    internal_engine_key: str = "threatlens-internal-dev-key-change-in-prod"
    http_timeout_seconds: float = 8.0
    enable_live_public_lookups: bool = True

    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    abuseipdb_api_key: str = ""
    alienvault_otx_api_key: str = ""
    nvd_api_key: str = ""

    ai_api_key: str = ""
    ai_base_url: str = "https://api.openai.com/v1"
    ai_model: str = "gpt-4o-mini"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
