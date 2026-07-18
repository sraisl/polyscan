"""End-to-end test: scan the vulnerable fixture and assert normalized findings."""
from pathlib import Path

from polyscan.core.engine import run_engines, all_findings
from polyscan.core.gate import QualityGate
from polyscan.core.schema import Severity

FIXTURE = Path(__file__).parent / "fixtures"


def test_scan_finds_vulns():
    results = run_engines(FIXTURE.resolve())
    findings = all_findings(results)
    assert findings, "expected at least one finding in fixtures"
    # all normalized with valid severity
    for f in findings:
        assert isinstance(f.severity, Severity)
        assert f.file


def test_quality_gate_fails_on_high():
    results = run_engines(FIXTURE.resolve())
    findings = all_findings(results)
    gate = QualityGate()
    passed, _ = gate.evaluate(findings)
    assert not passed, "gate should fail: fixtures contain high-severity issues"
