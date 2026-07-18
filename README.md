# PolyScan 🔍

**Lightweight multi-language SAST & code-quality orchestrator** — a self-hosted,
open-source alternative to SonarQube.

PolyScan does **not** reinvent parsers. It orchestrates best-of-breed OSS engines
(Semgrep, Bandit, ESLint, …) and normalizes their output into **one Finding schema**,
applies a **Quality Gate**, and renders reports for CLI, PR comments, and a web dashboard.

## Why not just use the engines directly?

| | Single engine | PolyScan |
|---|---|---|
| Multi-language | one tool per language | one command, all engines |
| Output format | each tool differs | unified Finding schema |
| Quality Gate | manual | built-in, exit-code |
| PR comment | DIY | Markdown report ready |
| History/Trend | none | planned dashboard |

## Install

```bash
pip install polyscan
# engines (any subset):
pip install semgrep bandit
npm install -g eslint
```

## Usage

```bash
# scan a repo (auto-detects languages via engines)
polyscan scan ./myrepo

# only Python + JS
polyscan scan ./myrepo -e bandit -e eslint

# JSON for CI / SARIF pipelines
polyscan scan ./myrepo --format json
```

### GitHub Action

```yaml
- uses: your-org/polyscan@v1
  with:
    target: "."
    engines: "semgrep,bandit,eslint"
```

## Quality Gate

Fails (exit 1) when:
- ≥ 1 critical finding, or
- ≥ 1 high finding, or
- ≥ 50 medium findings

Configure thresholds in `polyscan.core.gate.QualityGate`.

## Web Dashboard

```bash
uvicorn polyscan.server:app --port 8000
# open http://localhost:8000
# scan: GET /scan?target=/path/to/repo
```

## Roadmap

- [ ] SARIF export (GitHub Code Scanning compatible)
- [ ] Historical trends dashboard (per-branch/per-repo)
- [ ] More engines: golangci-lint, PMD, hadolint, Trivy (IaC)
- [ ] GitHub PR-Comment bot

## License

AGPL-3.0
