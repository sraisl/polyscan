"""Engine adapter base helpers."""
from __future__ import annotations

import subprocess
from pathlib import Path

from polyscan.core.schema import Severity


class EngineAdapter:
    CLI: str = ""

    @staticmethod
    def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            args, cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, timeout=300,
        )

    @staticmethod
    def _severity(s: str | None) -> Severity:
        if not s:
            return Severity.MEDIUM
        return {
            "info": Severity.INFO, "low": Severity.LOW,
            "medium": Severity.MEDIUM, "high": Severity.HIGH,
            "critical": Severity.CRITICAL, "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
        }.get(s.lower(), Severity.MEDIUM)
