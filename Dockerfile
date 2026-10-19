FROM python:3.11-slim AS base

LABEL maintainer="mrhenrike <henrique.santos@uniaogeek.com.br>"
LABEL org.opencontainers.image.source="https://github.com/mrhenrike/EmbedXPL-Forge"
LABEL org.opencontainers.image.description="EmbedXPL: embedded device exploitation framework"

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash xpluser

WORKDIR /opt/embedxpl

COPY pyproject.toml README.md LICENSE ./
COPY embedxpl/ embedxpl/

RUN pip install --no-cache-dir ".[firewalls,printers]"

USER xpluser

ENTRYPOINT ["embedxpl"]
CMD ["--help"]
