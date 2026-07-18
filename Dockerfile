FROM python:3.11-slim

LABEL org.opencontainers.image.title="PolyScan" \
      org.opencontainers.image.description="Lightweight multi-language SAST orchestrator"

# uv for locked, reproducible installs + Java for SpotBugs
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -s /root/.local/bin/uv /usr/local/bin/uv

ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY polyscan ./polyscan

# sync from the lockfile (reproducible), including dev/scan extras
RUN uv sync --frozen --extra dev --extra scan \
    && uv pip install --system . \
    && npm install -g eslint@8 || true

# Pre-fetch SpotBugs + FindSecBugs assets into the cache
RUN polyscan download-engines

ENTRYPOINT ["polyscan"]
CMD ["--help"]
