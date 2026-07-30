from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    DATABASE_URL: str = "sqlite:///./aidtip.db"
    LOG_LEVEL: str = "INFO"
    RULES_CONFIG_PATH: str = "backend/config/rules.yaml"
    PCAP_PATH: str = "samples/sample.pcap"
    CAPTURE_INTERFACE: str = "eth0"


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
