FROM python:3.11-slim

LABEL org.opencontainers.image.title="PolyScan" \
      org.opencontainers.image.description="Lightweight multi-language SAST orchestrator"

WORKDIR /app
COPY pyproject.toml README.md ./
COPY polyscan ./polyscan

RUN pip install --no-cache-dir . \
    && pip install --no-cache-dir semgrep bandit \
    && (npm install -g eslint@8 || true)

ENTRYPOINT ["polyscan"]
CMD ["--help"]
