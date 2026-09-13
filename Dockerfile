# Build the virtualenv with uv, then copy just the venv into a clean runtime
# image so uv and the build toolchain never ship.
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Dependencies first: editing src must not invalidate this layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev


FROM python:3.14-slim

# Fixed UID so the host data directory can be chowned to a known owner.
RUN useradd --create-home --uid 1000 sitemon

COPY --from=builder --chown=sitemon:sitemon /app /app
ENV PATH="/app/.venv/bin:$PATH"

USER sitemon
WORKDIR /data

ENTRYPOINT ["site-mon"]
CMD ["--config", "/config/config.toml", "--db", "/data/site-mon.db", "check"]
