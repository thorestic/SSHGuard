from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthResponse(ApiModel):
    status: str
    database: str
    api_version: str = "v1"


class Incident(ApiModel):
    id: int
    source_ip: str
    username: str | None
    attempt_count: int
    first_seen: datetime
    last_seen: datetime
    window_seconds: int
    status: str
    response_outcome: str | None


class AuthenticationEvent(ApiModel):
    id: int
    event_type: str
    username: str | None
    source_ip: str
    source_port: int | None
    invalid_user: bool
    timestamp: datetime


class FirewallAction(ApiModel):
    id: int
    source_ip: str
    action: str
    timestamp: datetime
    expires_at: datetime | None
    incident_id: int | None
    related_action_id: int | None


class Pagination(ApiModel):
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class IncidentList(ApiModel):
    items: list[Incident]
    pagination: Pagination


class AuthenticationEventList(ApiModel):
    items: list[AuthenticationEvent]
    pagination: Pagination


class FirewallActionList(ApiModel):
    items: list[FirewallAction]
    pagination: Pagination


class FirewallReconciliationResponse(ApiModel):
    status: Literal[
        "pending",
        "in_sync",
        "drift",
        "unavailable",
        "stale",
    ]
    checked_at: datetime | None
    expected_count: int = Field(ge=0)
    actual_count: int | None = Field(default=None, ge=0)
    missing_in_firewall: list[str]
    unexpected_in_firewall: list[str]
    error_code: str | None


class OverviewMetrics(ApiModel):
    incidents_total: int
    incidents_24h: int
    failed_logins_24h: int
    successful_logins_24h: int
    active_blocks: int
    unique_sources_24h: int


class OverviewResponse(ApiModel):
    generated_at: datetime
    metrics: OverviewMetrics
    recent_incidents: list[Incident]


class TimeBucket(ApiModel):
    bucket: datetime
    authentication_events: int
    incidents: int


class RankedValue(ApiModel):
    value: str
    count: int


class BreakdownValue(ApiModel):
    label: str
    count: int


class AnalyticsResponse(ApiModel):
    generated_at: datetime
    hours: int
    timeline: list[TimeBucket]
    top_sources: list[RankedValue]
    targeted_users: list[RankedValue]
    incident_statuses: list[BreakdownValue]
    response_outcomes: list[BreakdownValue]

