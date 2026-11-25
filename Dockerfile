# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM node:22-alpine AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM rust:1-bookworm AS backend-builder
WORKDIR /src/backend
COPY backend/Cargo.toml backend/Cargo.lock ./
# Pre-build dependencies with minimal dummy crate sources for layer caching.
RUN mkdir -p src \
    && printf 'pub fn dummy() {}\n' > src/lib.rs \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY backend/migrations ./migrations
COPY backend/src ./src
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --locked --bin rc-server \
    && strip /src/backend/target/release/rc-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 --system rcserver \
    && useradd --uid 10001 --gid rcserver --system --home-dir /app --shell /usr/sbin/nologin rcserver

WORKDIR /app
COPY --from=backend-builder /src/backend/target/release/rc-server /usr/local/bin/rc-server
COPY --from=web-builder /src/web/dist /app/web

ENV RC_HTTP_ADDR=0.0.0.0:21118 \
    RC_SIGNAL_ADDR=0.0.0.0:21116 \
    RC_RELAY_ADDR=0.0.0.0:21117 \
    RC_WEB_DIR=/app/web \
    RUST_LOG=info,rc_server=info,tower_http=info

EXPOSE 21116/tcp 21116/udp 21117/tcp 21118/tcp

USER rcserver

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD sh -ec 'addr="${RC_HTTP_ADDR:-0.0.0.0:21118}"; port="${addr##*:}"; case "$(printf "%s" "${RC_PLAIN_HTTP:-false}" | tr "[:upper:]" "[:lower:]")" in 1|true|yes|on) scheme=http ;; *) scheme=https ;; esac; curl -kfsS "${scheme}://127.0.0.1:${port}/api/v1/health" >/dev/null'

ENTRYPOINT ["/usr/local/bin/rc-server"]
