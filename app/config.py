"""Configuration for the GitHub App."""

import os
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # GitHub App credentials
    github_app_id: str = Field(..., description="GitHub App ID")
    github_app_private_key: str = Field(..., description="GitHub App private key (PEM format)")
    github_webhook_secret: str = Field(..., description="Webhook secret for signature verification")

    # Optional: GitHub Enterprise
    github_api_url: str = Field(
        default="https://api.github.com",
        description="GitHub API base URL",
    )

    # App settings
    app_name: str = Field(default="FedRAMP KSI App", description="Application name")
    log_level: str = Field(default="INFO", description="Logging level")
    environment: str = Field(default="production", description="Environment name")

    # Evidence artifact settings
    artifact_name_pattern: str = Field(
        default="evidence_ksi-mla-05_*",
        description="Pattern to match evidence artifacts",
    )
    results_artifact_name: str = Field(
        default="fedramp-ksi-results",
        description="Name of the results summary artifact",
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
