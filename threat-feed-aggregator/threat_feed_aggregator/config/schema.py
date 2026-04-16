"""
Pydantic models for config.json validation.

Usage:
    from .schema import validate_config
    errors = validate_config(config_dict)  # returns list of error strings, empty if valid
"""

import logging

from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)


class SourceConfig(BaseModel):
    name: str
    url: str
    format: str = "text"
    confidence: int = 50
    key_or_column: str | None = None
    auth_user: str | None = None
    auth_pass: str | None = None
    schedule_interval_minutes: int | None = None
    retention_days: int | None = None

    @field_validator("confidence")
    @classmethod
    def confidence_range(cls, v):
        if not 0 <= v <= 100:
            raise ValueError("confidence must be between 0 and 100")
        return v

    @field_validator("format")
    @classmethod
    def valid_format(cls, v):
        allowed = ("text", "json", "csv", "taxii")
        if v not in allowed:
            raise ValueError(f"format must be one of {allowed}")
        return v


class ProxyConfig(BaseModel):
    model_config = {"extra": "allow"}

    enabled: bool = False
    server: str | None = None
    port: int | None = None
    auth_user: str | None = None
    auth_pass: str | None = None
    username: str | None = None
    password: str | None = None


class DnsDedupSchedule(BaseModel):
    enabled: bool = False
    auto_delete: bool = False
    start_time: str = "00:00"
    end_time: str = "23:59"
    interval_minutes: int = 60
    batch_size: int = 50


class WebhookConfig(BaseModel):
    name: str = ""
    url: str
    events: list[str] = []


class AppConfig(BaseModel):
    """Top-level config schema. Uses model_config to allow extra fields for forward compat."""

    model_config = {"extra": "allow"}

    source_urls: list[SourceConfig] = []
    indicator_lifetime_days: int = 30
    timezone: str = "UTC"
    base_url: str = ""
    proxy: ProxyConfig = ProxyConfig()
    dns_dedup_schedule: DnsDedupSchedule = DnsDedupSchedule()
    webhooks: list[WebhookConfig] = []
    ssl_bypass_hosts: list[str] = []


def validate_config(config_dict):
    """
    Validate a config dict against the schema.
    Returns a list of error strings. Empty list means valid.
    """
    try:
        AppConfig.model_validate(config_dict)
        return []
    except Exception as e:
        errors = []
        if hasattr(e, "errors"):
            for err in e.errors():
                loc = " -> ".join(str(x) for x in err["loc"])
                errors.append(f"{loc}: {err['msg']}")
        else:
            errors.append(str(e))
        return errors
