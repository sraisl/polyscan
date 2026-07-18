FROM python:3.11-slim

LABEL org.opencontainers.image.title="PolyScan" \
      org.opencontainers.image.description="Lightweight multi-language SAST orchestrator"

# Java for the SpotBugs engine
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY polyscan ./polyscan

RUN pip install --no-cache-dir . \
    && pip install --no-cache-dir semgrep bandit \
    && (npm install -g eslint@8 || true)

# Pre-fetch SpotBugs + FindSecBugs assets into the cache
RUN polyscan download-engines

ENTRYPOINT ["polyscan"]
CMD ["--help"]
