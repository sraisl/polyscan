"""Test the SARIF exporter produces GitHub-compatible output."""
import json
from pathlib import Path

from polyscan.core.engine import run_engines, all_findings
from polyscan.core.sarif import build_sarif


def test_sarif_valid():
    findings = all_findings(run_engines(Path(__file__).parent / "fixtures"))
    sarif = build_sarif(findings, "tests/fixtures")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"]
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "PolyScan"
    assert driver["rules"]
    results = sarif["runs"][0]["results"]
    assert results
    for r in results:
        assert "ruleId" in r and "level" in r and "locations" in r
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert "partialFingerprints" in r


def test_sarif_rule_dedup():
    findings = all_findings(run_engines(Path(__file__).parent / "fixtures"))
    sarif = build_sarif(findings, "tests/fixtures")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
