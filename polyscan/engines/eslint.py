"""ESLint adapter — JavaScript / TypeScript code quality & security."""
from __future__ import annotations

import json
from pathlib import Path

from polyscan.core.schema import EngineResult, Finding
from polyscan.engines.base import EngineAdapter

CLI = "eslint"


def run(target: Path) -> EngineResult:
    proc = EngineAdapter._run(
        ["eslint", str(target), "-f", "json",
         "--no-config-lookup", "--rule", '{"no-eval":"error"}'],
    )
    findings: list[Finding] = []
    errors: list[str] = []
    # ESLint returns non-zero when lint errors exist; that's expected.
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        errors.append(proc.stderr[:500])
        return EngineResult(engine="eslint", findings=[], errors=errors)

    for file_res in data:
        fname = file_res.get("filePath", "")
        for msg in file_res.get("messages", []):
            sev = "high" if msg.get("severity") == 2 else "medium"
            findings.append(
                Finding(
                    engine="eslint",
                    rule_id=msg.get("ruleId") or "unknown",
                    severity=sev,
                    language="js",
                    file=fname,
                    line=msg.get("line"),
                    column=msg.get("column"),
                    message=msg.get("message", ""),
                )
            )
    return EngineResult(engine="eslint", findings=findings, errors=errors)
