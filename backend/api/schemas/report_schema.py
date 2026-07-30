"""Report API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ReportCreateRequest(BaseModel):
    start: datetime
    end: datetime


class ReportSummaryResponse(BaseModel):
    id: UUID
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    summary: dict[str, Any]
    top_attackers: list[dict[str, Any]] = Field(default_factory=list)
    top_ports: list[dict[str, Any]] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
