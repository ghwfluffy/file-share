from __future__ import annotations

from functools import lru_cache
from secrets import token_urlsafe
from urllib.parse import urlsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def normalize_path_prefix(value: str) -> str:
    trimmed = value.strip()
    if trimmed in {"", "/"}:
        return ""
    with_leading_slash = trimmed if trimmed.startswith("/") else f"/{trimmed}"
    return with_leading_slash.rstrip("/")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    app_env: str = "development"
    app_name: str = "File Share"
    public_url: str = "http://localhost:8000"
    management_base_path: str = "/files"
    share_base_path: str = "/public-files"
    auth_base_url: str = "/auth"
    federated_goals_base_url: str = ""
    federated_money_planner_base_url: str = ""
    federated_agent_base_url: str = ""
    federated_apartment_gate_base_url: str = ""
    federated_file_share_base_url: str = ""
    oauth_server_base_url: str | None = None
    oauth_client_id: str = "file-share"
    oauth_scope: str = "openid profile"
    oauth_state_cookie_name: str = "file_share_oauth_state"
    session_cookie_name: str = "file_share_session"
    session_duration_minutes: int = 1440
    session_key: str | None = None
    postgres_user: str = "ghw_file_share"
    postgres_password: str = ""
    postgres_db: str = "file_share"
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    max_upload_bytes: int = 100 * 1024 * 1024
    default_link_lifetime_hours: int = 24
    thumbnail_max_dimension: int = 360
    max_image_resize_dimension: int = 4096

    @field_validator("public_url")
    @classmethod
    def public_url_must_be_origin(cls, value: str) -> str:
        parsed = urlsplit(value.rstrip("/"))
        if parsed.path not in {"", "/"}:
            raise ValueError("PUBLIC_URL must be only the scheme and host; put prefixes in route settings.")
        return value.rstrip("/")

    @property
    def database_url(self) -> str:
        return (
            "postgresql+psycopg2://"
            f"{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def normalized_management_base_path(self) -> str:
        return normalize_path_prefix(self.management_base_path) or "/files"

    @property
    def normalized_share_base_path(self) -> str:
        return normalize_path_prefix(self.share_base_path) or "/public-files"

    @property
    def public_origin(self) -> str:
        return self.public_url.rstrip("/")

    @property
    def public_management_base_url(self) -> str:
        return f"{self.public_origin}{self.normalized_management_base_path}"

    @property
    def normalized_auth_base_url(self) -> str:
        raw = self.auth_base_url.rstrip("/")
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        return f"{self.public_origin}{normalize_path_prefix(raw)}"

    def browser_base_url(self, value: str) -> str:
        raw = value.rstrip("/")
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        return normalize_path_prefix(raw)

    @property
    def federated_banner_sites(self) -> list[dict[str, str]]:
        entries = [
            ("federated-services", "Federated Services", self.auth_base_url, "Account settings and federated service administration."),
            ("goals", "Goal Tracker", self.federated_goals_base_url, "Goals, metrics, dashboards, and progress widgets."),
            ("money-planner", "Fluffynomics", self.federated_money_planner_base_url, "Accounts, expenses, contracts, investments, and net worth."),
            ("agent", "AI Assistant", self.federated_agent_base_url, "Assistant tasks, mailbox workflows, and audited agent activity."),
            ("apartment-gate", "Apartment Gate", self.federated_apartment_gate_base_url, "Protected apartment gate and door controls."),
            ("file-share", "File Share", self.federated_file_share_base_url or self.management_base_path, "Uploads, expiring share links, and revocation."),
        ]
        return [
            {"slug": slug, "name": name, "baseUrl": self.browser_base_url(base_url), "description": description}
            for slug, name, base_url, description in entries
            if base_url.strip()
        ]

    @property
    def account_settings_url(self) -> str:
        return f"{self.browser_base_url(self.auth_base_url)}?tab=profile"

    @property
    def normalized_oauth_server_base_url(self) -> str:
        raw = (self.oauth_server_base_url or self.auth_base_url).rstrip("/")
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        return f"{self.public_origin}{normalize_path_prefix(raw)}"

    @property
    def oauth_redirect_uri(self) -> str:
        return f"{self.public_management_base_url}/auth/oauth/callback"

    @property
    def cookie_secure(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.session_key:
        settings.session_key = token_urlsafe(32)
    return settings
