"""Application settings, loaded from environment variables or an optional .env file."""
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="POLICYPULSE_", env_file=".env", extra="ignore"
    )

    app_name: str = "PolicyPulse"
    environment: str = "development"
    database_url: str = "sqlite:///./data/policypulse.db"
    # Comma-separated list of allowed browser origins for CORS.
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    max_request_bytes: int = Field(default=65536, ge=1024, le=1_048_576)
    max_page_size: int = Field(default=100, ge=1, le=500)
    export_max_rows: int = Field(default=10000, ge=1, le=100000)
    dashboard_activity_window: int = Field(default=1000, ge=10, le=10000)

    @field_validator("cors_origins")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip() and o.strip() != "*"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
