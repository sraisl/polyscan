"""PolyScan CLI."""
from __future__ import annotations

import json
from pathlib import Path

import click

from polyscan.core.engine import run_engines, all_findings
from polyscan.core.gate import QualityGate
from polyscan.core.schema import Severity


@click.group()
@click.version_option(version="0.1.0")
def cli() -> None:
    """PolyScan — lightweight multi-language SAST orchestrator."""


@cli.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option("--engines", "-e", multiple=True, help="Engines to run (semgrep, bandit, eslint)")
@click.option("--format", "fmt", type=click.Choice(["md", "json", "table"]), default="md")
@click.option("--gate/--no-gate", default=True, help="Apply Quality Gate (exit 1 on fail)")
def scan(target: Path, engines: tuple[str, ...], fmt: str, gate: bool) -> None:
    """Scan TARGET and report normalized findings."""
    selected = list(engines) if engines else None
    results = run_engines(target, selected)
    findings = all_findings(results)

    if fmt == "json":
        click.echo(json.dumps([f.model_dump() for f in findings], indent=2, default=str))
    elif fmt == "table":
        for f in findings:
            click.echo(f"{f.severity.value.upper():8} {f.engine:8} {f.file}:{f.line}  {f.rule_id}")
    else:
        click.echo(render_md(results, findings))

    if gate and findings:
        g = QualityGate()
        passed, msg = g.evaluate(findings)
        click.echo(f"\n{msg}")
        if not passed:
            raise SystemExit(1)


def render_md(results, findings) -> str:
    lines = ["## 🔍 PolyScan Report", ""]
    by_sev = {s: 0 for s in Severity}
    for f in findings:
        by_sev[f.severity] += 1
    lines.append(
        " | ".join(f"{s.value}: {by_sev[s]}" for s in Severity)
    )
    lines.append("")

    # engine status
    for r in results:
        status = "✅" if not r.skipped else "⚠️"
        lines.append(f"{status} {r.engine}: {len(r.findings)} findings" +
                     (f" — {r.errors[0]}" if r.errors else ""))
    lines.append("")

    if not findings:
        lines.append("✨ No findings. Clean code!")
        return "\n".join(lines)

    lines.append("### Findings")
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        lines.append(f.to_md())
    return "\n".join(lines)


@cli.command()
def download_engines() -> None:
    """Download optional engine assets (SpotBugs JARs) into the cache."""
    from polyscan.engines import spotbugs_data as data

    print("Resolving cache dir:", data.cache_root())
    ok = data.ensure(force=True)
    if ok:
        print("✅ SpotBugs assets ready.")
    else:
        raise SystemExit(1)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
