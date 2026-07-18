"""PolyScan — lightweight multi-language SAST orchestrator.

A self-hosted SonarQube alternative: runs best-of-breed OSS engines
(Semgrep, Bandit, ESLint, ...) and normalizes their output into one
Finding schema, applies a Quality Gate, and renders reports.
"""
from polyscan.core.schema import Finding, Severity
from polyscan.core.engine import run_engines, EngineResult

__all__ = ["Finding", "Severity", "run_engines", "EngineResult"]
__version__ = "0.1.0"
