"""Normalized Finding schema — engine-agnostic."""
from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Finding(BaseModel):
    engine: str
    rule_id: str
    severity: Severity
    language: str = "unknown"
    file: str
    line: int | None = None
    column: int | None = None
    message: str
    cwe: str | None = None
    remediation: str | None = None
    snippet: str | None = None

    def to_md(self) -> str:
        loc = self.file
        if self.line is not None:
            loc += f":{self.line}"
        sev = self.severity.value.upper()
        extra = f" ({self.cwe})" if self.cwe else ""
        return f"- **{sev}** `{self.rule_id}`{extra}: {self.message}\n  📄 {loc}"


class EngineResult(BaseModel):
    engine: str
    findings: list[Finding]
    errors: list[str] = Field(default_factory=list)
    skipped: bool = False
