from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Verdict = Literal["LOW", "CAUTION", "HIGH", "UNKNOWN"]


class CheckRequest(BaseModel):
    content: str = Field(default="", max_length=20_000)
    source_hint: str = Field(default="", max_length=64)
    household_id: str = Field(default="", max_length=128)

    @field_validator("content")
    @classmethod
    def strip_content(cls, v: str) -> str:
        return (v or "").strip()


class Indicator(BaseModel):
    kind: str
    value: str
    note: str = ""


class EvidenceItem(BaseModel):
    code: str
    detail: str
    weight: int = 0
    source: str = "heuristic"


class IntelResult(BaseModel):
    provider: str
    status: Literal["ok", "skipped", "error", "unknown"]
    summary: str
    raw: dict[str, Any] = Field(default_factory=dict)


class CheckResponse(BaseModel):
    check_id: str
    verdict: Verdict
    score: int
    summary: str
    evidence: list[EvidenceItem]
    indicators: list[Indicator]
    actions: list[str]
    intel: list[IntelResult]
    policy: dict[str, Any]
    content_stored: bool = False


class HealthResponse(BaseModel):
    status: str
    version: str
    intel: dict[str, str]
