"""Engine registry + runner."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from polyscan.core.schema import EngineResult, Finding, Severity
from polyscan.engines import semgrep, bandit, eslint, spotbugs

ENGINES = {
    "semgrep": semgrep,
    "bandit": bandit,
    "eslint": eslint,
    "spotbugs": spotbugs,
}

SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
}


def _available(name: str) -> bool:
    cmd = ENGINES[name].CLI
    return shutil.which(cmd) is not None


def run_engines(
    target: Path, engines: list[str] | None = None
) -> list[EngineResult]:
    target = target.resolve()
    selected = engines or list(ENGINES.keys())
    results: list[EngineResult] = []
    for name in selected:
        if name not in ENGINES:
            continue
        if not _available(name):
            results.append(
                EngineResult(
                    engine=name,
                    findings=[],
                    errors=[f"{ENGINES[name].CLI} not installed — skipped"],
                    skipped=True,
                )
            )
            continue
        try:
            # pass absolute path, no cwd change (engines resolve relative to path)
            results.append(ENGINES[name].run(target))
        except Exception as e:  # engine crashed
            results.append(
                EngineResult(
                    engine=name, findings=[], errors=[f"{name} error: {e}"]
                )
            )
    return results


def all_findings(results: list[EngineResult]) -> list[Finding]:
    out: list[Finding] = []
    for r in results:
        out.extend(r.findings)
    return out
