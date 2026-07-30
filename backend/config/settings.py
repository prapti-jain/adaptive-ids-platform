from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_LOCAL_ORIGINS = (
    "http://localhost:5173,"
    "http://127.0.0.1:5173,"
    "http://localhost:5174,"
    "http://127.0.0.1:5174"
)


class Settings(BaseSettings):
    """Application settings loaded from environment / ``.env``.

    ``DATABASE_URL`` is required — there is no silent SQLite fallback. Local
    development sets ``DATABASE_URL=sqlite:///./aidtip.db`` in ``.env``;
    production (Render + Neon) must provide a Postgres URL explicitly.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    DATABASE_URL: str
    LOG_LEVEL: str = "INFO"
    RULES_CONFIG_PATH: str = "backend/config/rules.yaml"
    PCAP_PATH: str = "samples/sample.pcap"
    CAPTURE_INTERFACE: str = "eth0"
    ALLOWED_ORIGINS: str = _DEFAULT_LOCAL_ORIGINS

    @field_validator("DATABASE_URL")
    @classmethod
    def normalize_database_url(cls, value: str) -> str:
        """Normalize Neon/Heroku-style ``postgres://`` to SQLAlchemy's scheme."""
        value = value.strip()
        if not value:
            raise ValueError("DATABASE_URL must not be empty")
        if value.startswith("postgres://"):
            return "postgresql://" + value.removeprefix("postgres://")
        return value

    def allowed_origins_list(self) -> list[str]:
        """Parse comma-separated ``ALLOWED_ORIGINS`` into a CORS allow-list."""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]


settings = Settings()


@lru_cache
def load_rules_config() -> dict[str, Any]:
    """Load detection rule thresholds from the configured YAML file."""
    path = Path(settings.RULES_CONFIG_PATH)
    if not path.is_file():
        raise FileNotFoundError(f"Rules config not found: {path}")
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Rules config must be a mapping: {path}")
    return data
