"""Quality Gate logic."""
from __future__ import annotations

from polyscan.core.schema import Finding, Severity


class QualityGate:
    """Fail the build if findings exceed configured thresholds."""

    def __init__(
        self,
        max_critical: int = 0,
        max_high: int = 0,
        max_medium: int = 50,
        fail_on: tuple[Severity, ...] = (Severity.CRITICAL, Severity.HIGH),
    ):
        self.max_critical = max_critical
        self.max_high = max_high
        self.max_medium = max_medium
        self.fail_on = fail_on

    def evaluate(self, findings: list[Finding]) -> tuple[bool, str]:
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1

        reasons = []
        if counts[Severity.CRITICAL] > self.max_critical:
            reasons.append(
                f"{counts[Severity.CRITICAL]} critical (max {self.max_critical})"
            )
        if counts[Severity.HIGH] > self.max_high:
            reasons.append(f"{counts[Severity.HIGH]} high (max {self.max_high})")
        if counts[Severity.MEDIUM] > self.max_medium:
            reasons.append(
                f"{counts[Severity.MEDIUM]} medium (max {self.max_medium})"
            )

        passed = not reasons
        msg = (
            "✅ Quality Gate passed"
            if passed
            else "❌ Quality Gate failed: " + "; ".join(reasons)
        )
        return passed, msg
