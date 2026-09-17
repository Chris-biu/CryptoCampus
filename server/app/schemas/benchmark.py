from __future__ import annotations

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class JobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iterations: int = Field(default=1000, ge=10, le=10000, description="迭代次数，10..10000")
    include_pqc: bool = Field(default=True, description="是否包含抗量子测试")


class JobResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: datetime


class BenchmarkMetricResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: str
    mean_ms: float
    p99_ms: float
    pqc_overhead_percent: float | None = None


class BenchmarkResultResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    status: Literal["queued", "running", "completed", "failed"]
    metrics: list[BenchmarkMetricResponse]
    created_at: datetime
