"""Bandit adapter — Python SAST."""
from __future__ import annotations

import json
from pathlib import Path

from polyscan.core.schema import EngineResult, Finding
from polyscan.engines.base import EngineAdapter

CLI = "bandit"


def run(target: Path) -> EngineResult:
    proc = EngineAdapter._run(
        ["bandit", "-q", "-f", "json", "-r", str(target)],
    )
    findings: list[Finding] = []
    errors: list[str] = []
    if proc.returncode not in (0, 1):
        errors.append(proc.stderr[:300])
    # bandit may print warnings to stdout; extract the JSON object only
    stdout = proc.stdout or "{}"
    start = stdout.find("{")
    try:
        data = json.loads(stdout[start:]) if start >= 0 else {}
    except json.JSONDecodeError:
        errors.append("bandit output not JSON")
        return EngineResult(engine="bandit", findings=[], errors=errors)

    sev_map = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
    for r in data.get("results", []):
        findings.append(
            Finding(
                engine="bandit",
                rule_id=r.get("test_id", "B"),
                severity=sev_map.get(r.get("issue_severity", "MEDIUM"), "medium"),
                language="python",
                file=r.get("filename", ""),
                line=r.get("line_number"),
                message=r.get("issue_text", ""),
                cwe=r.get("cwe"),
                snippet=r.get("code"),
            )
        )
    return EngineResult(engine="bandit", findings=findings, errors=errors)
