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
@click.option("--engines", "-e", multiple=True, help="Engines to run (semgrep, bandit, eslint, spotbugs)")
@click.option("--format", "fmt", type=click.Choice(["md", "json", "table", "sarif"]), default="md")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write report to file (e.g. polyscan.sarif)")
@click.option("--gate/--no-gate", default=True, help="Apply Quality Gate (exit 1 on fail)")
@click.option("--max-critical", default=0, show_default=True, help="Max critical findings before gate fails")
@click.option("--max-high", default=0, show_default=True, help="Max high findings before gate fails")
@click.option("--max-medium", default=50, show_default=True, help="Max medium findings before gate fails")
def scan(target: Path, engines: tuple[str, ...], fmt: str, output: Path | None,
          gate: bool, max_critical: int, max_high: int, max_medium: int) -> None:
    """Scan TARGET and report normalized findings."""
    selected = list(engines) if engines else None
    results = run_engines(target, selected)
    findings = all_findings(results)

    if fmt == "json":
        text = json.dumps([f.model_dump() for f in findings], indent=2, default=str)
    elif fmt == "table":
        lines = [f"{f.severity.value.upper():8} {f.engine:8} {f.file}:{f.line}  {f.rule_id}"
                 for f in findings]
        text = "\n".join(lines)
    elif fmt == "sarif":
        from polyscan.core.sarif import build_sarif
        text = json.dumps(build_sarif(findings, target), indent=2)
    else:
        text = render_md(results, findings)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
        click.echo(f"Report written to {output}")
    else:
        click.echo(text)

    if gate and findings:
        g = QualityGate(max_critical=max_critical, max_high=max_high, max_medium=max_medium)
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
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write SBOM to file (e.g. bom.json)")
def sbom(target: Path, output: Path | None) -> None:
    """Generate a CycloneDX SBOM from dependency manifests in TARGET."""
    import json

    from polyscan.core.sbom import build_sbom

    bom = build_sbom(target)
    text = json.dumps(bom, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
        click.echo(f"SBOM ({len(bom['components'])}) written to {output}")
    else:
        click.echo(text)


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
