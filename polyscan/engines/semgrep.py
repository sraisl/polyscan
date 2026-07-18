"""Semgrep adapter — universal multi-language SAST engine."""
from __future__ import annotations

import json
from pathlib import Path

from polyscan.core.schema import EngineResult, Finding, Severity
from polyscan.engines.base import EngineAdapter

CLI = "semgrep"


def run(target: Path) -> EngineResult:
    # Prefer bundled rules; fall back to auto (needs network/login).
    rule_cfg = str(Path(__file__).parent.parent / "rules" / "semgrep.yml")
    cfg = rule_cfg if Path(rule_cfg).exists() else "p/ci"
    proc = EngineAdapter._run(
        ["semgrep", "--config", cfg, "--json", "--quiet", str(target)],
    )
    findings: list[Finding] = []
    errors: list[str] = []
    if proc.returncode not in (0, 1):
        errors.append(proc.stderr[:500])
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        data = {}
    for r in data.get("results", []):
        loc = r.get("path", "")
        start = (r.get("start") or {})
        extra = r.get("extra", {})
        sev = EngineAdapter._severity(extra.get("severity"))
        check_id = r.get("check_id", "unknown")
        # strip bundle path prefix -> keep rule name only
        if "." in check_id and len(check_id) > 40:
            check_id = check_id.split(".")[-1]
        findings.append(
            Finding(
                engine="semgrep",
                rule_id=check_id,
                severity=sev,
                language=r.get("language", "unknown"),
                file=loc,
                line=start.get("line"),
                column=start.get("col"),
                message=extra.get("message", ""),
                cwe=_cwe(extra),
                remediation=_fix(extra),
                snippet=extra.get("lines"),
            )
        )
    return EngineResult(engine="semgrep", findings=findings, errors=errors)


def _cwe(extra: dict) -> str | None:
    for m in extra.get("metadata", {}).get("cwe", []):
        return str(m)
    return None


def _fix(extra: dict) -> str | None:
    fix = extra.get("fix")
    return str(fix) if fix else None
