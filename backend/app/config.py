"""SentinelAI Configuration."""

import os
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    APP_NAME: str = "SentinelAI"
    APP_ENV: str = "development"
    LOG_LEVEL: str = "info"

    # Database
    DATABASE_URL: str = "sqlite:///./sentinel.db"

    # CORS
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:3001"

    # Gemini API
    GEMINI_API_KEY: str = ""

    # Processing
    DEDUP_TIME_WINDOW_SECONDS: int = 60
    CORRELATION_TIME_WINDOW_MINUTES: int = 30
    BRUTE_FORCE_THRESHOLD: int = 10
    PORT_SCAN_THRESHOLD: int = 20
    PASSWORD_SPRAY_USER_THRESHOLD: int = 5

    # Risk scoring weights (must sum to 1.0)
    RISK_WEIGHT_SEVERITY: float = 0.30
    RISK_WEIGHT_ASSET_CRITICALITY: float = 0.25
    RISK_WEIGHT_BEHAVIORAL_ANOMALY: float = 0.20
    RISK_WEIGHT_ATTACK_PATTERN: float = 0.15
    RISK_WEIGHT_CORROBORATING: float = 0.10

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
