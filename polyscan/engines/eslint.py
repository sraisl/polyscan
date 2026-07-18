"""ESLint adapter — JavaScript / TypeScript code quality & security."""
from __future__ import annotations

import json
import os
from pathlib import Path

from polyscan.core.schema import EngineResult, Finding
from polyscan.engines.base import EngineAdapter

CLI = "eslint"


def run(target: Path) -> EngineResult:
    # Use typescript-eslint via a temporary flat-config so .ts parses.
    ts_cache = "/root/.hermes/cache/eslint-ts/node_modules"
    env = dict(os.environ)
    if Path(ts_cache).exists():
        env["NODE_PATH"] = ts_cache

    # Point the flat config at the absolute TS parser path (ESM ignores NODE_PATH)
    parser_path = f"{ts_cache}/@typescript-eslint/parser/dist/index.js"
    config = (
        f"import tsParser from '{parser_path}';\n"
        "export default [\n"
        "  {\n"
        "    files: ['**/*.{js,ts,jsx,tsx}'],\n"
        "    languageOptions: { parser: tsParser },\n"
        "    rules: { 'no-eval': 'error' },\n"
        "  },\n"
        "];\n"
    )
    config_path = target / "eslint.config.mjs"
    created = False
    if not config_path.exists() and Path(parser_path).exists():
        config_path.write_text(config)
        created = True

    proc = EngineAdapter._run(
        ["eslint", str(target), "-f", "json"],
        env=env,
    )
    if created:
        config_path.unlink(missing_ok=True)
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
