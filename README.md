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
# with uv (recommended — uses uv.lock for reproducible installs)
uv sync --extra dev --extra scan
uv run polyscan scan ./myrepo

# or classic pip
pip install polyscan
pip install semgrep bandit
npm install -g eslint
```

### Install with uv

```bash
# create lockfile and project venv
uv lock
uv sync --extra dev --extra scan

# eslint is a Node tool and remains npm-managed
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

# SARIF (GitHub code scanning compatible) -> file
polyscan scan ./myrepo --format sarif -o polyscan.sarif

# CycloneDX SBOM from dependency manifests
polyscan sbom ./myrepo -o bom.json
```

With uv:

```bash
uv run polyscan scan ./myrepo
uv run polyscan sbom ./myrepo -o bom.json
```

### Run via Docker

PolyScan ships a container image (published to GHCR on every `main` push):

```bash
# pull from GHCR (auto-built by CI)
docker pull ghcr.io/sraisl/polyscan:latest

# scan a local repo — mount it at /code
docker run --rm \
  -v /pfad/zu/deinem/repo:/code \
  ghcr.io/sraisl/polyscan:latest scan /code \
  -e semgrep -e bandit -e eslint --format md

# SARIF into a host volume
docker run --rm \
  -v /pfad/zu/deinem/repo:/code \
  -v $(pwd)/out:/out \
  ghcr.io/sraisl/polyscan:latest scan /code \
  --format sarif -o /out/polyscan.sarif

# SBOM
docker run --rm \
  -v /pfad/zu/deinem/repo:/code \
  -v $(pwd)/out:/out \
  ghcr.io/sraisl/polyscan:latest sbom /code -o /out/bom.json
```

Or build the image locally (no publish needed):

```bash
docker build -t polyscan:local .
docker run --rm -v $(pwd):/code polyscan:local scan /code --format md
```

### GitHub Action

PolyScan ships as a reusable Action (Docker-based, image from GHCR). Drop it into any workflow:

```yaml
jobs:
  polyscan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # upload SARIF to code scanning
      contents: read
    steps:
      - uses: actions/checkout@v7

      - name: PolyScan self-scan
        uses: sraisl/polyscan@v1
        with:
          target: "."
          engines: "semgrep,bandit,eslint"   # add "spotbugs" for Java/Kotlin
          format: "sarif"

      - name: Upload SARIF to GitHub code scanning
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: polyscan.sarif

      - name: Job Summary
        if: always()
        run: cat polyscan-summary.md >> "$GITHUB_STEP_SUMMARY"
```

The Action writes two artifacts into the runner workspace:
- `polyscan.sarif` — consumed by `upload-sarif`
- `polyscan-summary.md` — a Markdown report you can pipe into `$GITHUB_STEP_SUMMARY` (shown above) or post as a PR comment.

Notes:
- The Action pulls `ghcr.io/sraisl/polyscan:latest` (auto-built & pushed by this repo's CI on every `main` push).
- Pin to a release tag (e.g. `sraisl/polyscan@v1`) — Dependabot will bump it to `@v2` automatically when released (configued with `versioning-strategy: increase`). `@main` is not tracked by Dependabot.
- Add `spotbugs` to `engines` for Java/Kotlin (needs a JDK on the runner; the action installs one if missing).

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

- [x] SARIF export (GitHub Code Scanning compatible)
- [x] CycloneDX SBOM
- [x] Docker image published to GHCR
- [ ] Historical trends dashboard (per-branch/per-repo)
- [ ] More engines: golangci-lint, PMD, hadolint, Trivy (IaC)
- [ ] GitHub PR-Comment bot

## License

AGPL-3.0
