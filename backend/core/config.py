"""
Application Configuration
Manages all application settings via environment variables
"""
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Application
    APP_NAME: str = "VulnScan Platform"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "vulnscan"
    POSTGRES_PASSWORD: str = "vulnscan"
    POSTGRES_DB: str = "vulnscan"

    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    # Redis / Celery
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    @property
    def REDIS_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def CELERY_BROKER_URL(self) -> str:
        return self.REDIS_URL

    @property
    def CELERY_RESULT_BACKEND(self) -> str:
        return self.REDIS_URL

    # HashiCorp Vault
    VAULT_ADDR: str = "http://localhost:8200"
    VAULT_TOKEN: Optional[str] = None
    VAULT_MOUNT_POINT: str = "secret"
    VAULT_PATH_PREFIX: str = "vulnscan"

    # Neo4j (Graph Database)
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"

    # Security
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_USE_STRONG_RANDOM_KEY"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # CORS
    CORS_ORIGINS: list = ["http://localhost:3000", "http://localhost:5173"]

    # Scanning Configuration
    SCAN_WORKER_TIMEOUT: int = 3600  # 1 hour default
    MAX_CONCURRENT_SCANS: int = 10
    MASSCAN_RATE: int = 1000  # packets per second
    NMAP_TIMING: str = "T4"  # Aggressive timing

    # Plugin Configuration
    PLUGIN_DIR: str = "/app/plugins"
    PLUGIN_TIMEOUT: int = 1800  # 30 minutes

    # Approval Workflow
    REQUIRE_APPROVAL_INTRUSIVE: bool = True
    REQUIRE_APPROVAL_EXPLOIT: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
