# One build file, one target per role. All images run as the same unprivileged user (uid 10001) and are
# meant to be started read-only with every capability dropped (see docker-compose.yml).
#
#   docker build -f docker/Dockerfile --target honeypot  -t honeynet/honeypot:local  .
#   docker build -f docker/Dockerfile --target analyzer  -t honeynet/analyzer:local  .
#   docker build -f docker/Dockerfile --target dashboard -t honeynet/dashboard:local  .
#   docker build -f docker/Dockerfile --target fetcher   -t honeynet/fetcher:local    .

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HONEYNET_DATA_DIR=/data
RUN groupadd --gid 10001 honeynet \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin honeynet \
 && mkdir -p /data && chown 10001:10001 /data
WORKDIR /build
COPY pyproject.toml ./
COPY src ./src

# ---- honeypot: SSH / Telnet / HTTP / MySQL / Redis (one service per container) -------------------------
FROM base AS honeypot
RUN pip install ".[honeypot]" && cd / && rm -rf /build
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["honeynet", "run"]
CMD ["ssh"]

# ---- analyzer: static analysis of quarantined files, run with --network none ---------------------------
FROM base AS analyzer
RUN pip install ".[analysis]" && cd / && rm -rf /build
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["honeynet"]
CMD ["analyze"]

# ---- dashboard -------------------------------------------------------------------------------------
FROM base AS dashboard
RUN pip install ".[dashboard]" && cd / && rm -rf /build
USER 10001:10001
WORKDIR /data
ENV HONEYNET_DASHBOARD_HOST=0.0.0.0
ENTRYPOINT ["honeynet"]
CMD ["dashboard"]

# ---- fetcher: the only container allowed (narrow) internet egress, optional ------------------------------
FROM base AS fetcher
RUN pip install "." && cd / && rm -rf /build
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["honeynet"]
CMD ["fetcher"]
