"""PolyScan web server — minimal scan API + dashboard."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

from polyscan.core.engine import run_engines, all_findings
from polyscan.core.gate import QualityGate
from polyscan.core.schema import Severity

app = FastAPI(title="PolyScan", version="0.1.0")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/scan")
def scan(target: str = Query(...), engines: str | None = None):
    path = Path(target)
    if not path.exists():
        return JSONResponse({"error": "target not found"}, status_code=404)
    selected = engines.split(",") if engines else None
    results = run_engines(path, selected)
    findings = all_findings(results)
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    gate = QualityGate()
    passed, msg = gate.evaluate(findings)
    return {
        "target": str(path),
        "counts": counts,
        "gate": {"passed": passed, "message": msg},
        "findings": [f.model_dump() for f in findings],
    }


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
    <!doctype html><html><head><meta charset="utf-8">
    <title>PolyScan</title><style>body{font-family:system-ui;margin:2rem;background:#0d1117;color:#e6edf3}
    code{background:#161b22;padding:.2rem .4rem;border-radius:4px}</style></head>
    <body><h1>🔍 PolyScan</h1>
    <p>Lightweight multi-language SAST orchestrator.</p>
    <p>Scan an endpoint: <code>GET /scan?target=/path/to/repo</code></p>
    <p>CLI: <code>polyscan scan &lt;path&gt;</code></p>
    <p><a href="https://github.com/HKUDS" style="color:#58a6ff">Docs &amp; source</a></p>
    </body></html>
    """
