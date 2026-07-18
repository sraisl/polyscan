"""Test Quality Gate threshold overrides via CLI flags / inputs."""
from polyscan.core.gate import QualityGate
from polyscan.core.schema import Finding, Severity


def _f(sev: Severity) -> Finding:
    return Finding(engine="semgrep", rule_id="t", file="x.py", line=1,
                 severity=sev, message="m", cwe=None)


def test_default_gate_fails_on_high():
    g = QualityGate()
    passed, _ = g.evaluate([_f(Severity.HIGH)])
    assert passed is False


def test_custom_threshold_passes_high():
    g = QualityGate(max_high=5)
    passed, _ = g.evaluate([_f(Severity.HIGH)] * 3)
    assert passed is True


def test_custom_threshold_fails_medium():
    g = QualityGate(max_medium=2)
    passed, _ = g.evaluate([_f(Severity.MEDIUM)] * 4)
    assert passed is False
