"""SARIF 2.1.0 exporter — GitHub Code Scanning compatible."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from polyscan.core.schema import Finding, Severity

# SARIF severity -> GitHub security severity
SEV_TO_SARIF = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

TOOL_DRIVER = "PolyScan"
VERSION = "0.1.0"


def _rule_id(f: Finding) -> str:
    return f"{f.engine}/{f.rule_id}"


def build_sarif(findings: list[Finding], target: str | Path) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "shortDescription": {"text": f"{f.engine}: {f.rule_id}"},
                "fullDescription": {"text": f.message},
                "properties": {"tags": [f.engine, f.language]},
            }
            if f.cwe:
                rules[rid]["properties"]["cwe"] = f.cwe
        level = SEV_TO_SARIF[f.severity]
        artifact = f.file or "unknown"
        region = {"startLine": f.line or 1}
        if f.column:
            region["startColumn"] = f.column
        results.append(
            {
                "ruleId": rid,
                "level": level,
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(artifact)},
                            "region": region,
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": _hash(f)
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_DRIVER,
                        "version": VERSION,
                        "informationUri": "https://github.com/sraisl/polyscan",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def _hash(f: Finding) -> str:
    # stable fingerprint from engine+rule+file+line
    return uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"{f.engine}:{f.rule_id}:{f.file}:{f.line}",
    ).hex


def write_sarif(findings: list[Finding], target: str | Path, out_path: Path) -> None:
    sarif = build_sarif(findings, target)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(__import__("json").dumps(sarif, indent=2))
