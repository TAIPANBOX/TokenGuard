# TokenFuse gateway — portable container image.
#
# Runs anywhere (any host, any cloud, Kubernetes) — no dependence on a
# particular server. Published to GitHub Container Registry by
# .github/workflows/release.yml:
#
#   docker run -p 4100:4100 ghcr.io/taipanbox/tokenfuse
#   docker run -p 4100:4100 -e TOKENFUSE_UPSTREAM=https://api.anthropic.com/v1/messages \
#     ghcr.io/taipanbox/tokenfuse
#
# Builds the default gateway (drop-in proxy). Pass FEATURES=cluster to bake in
# the raft HA stack (the `:cluster` image tag); onnx/wasm are also opt-in.
#
#   docker build --build-arg FEATURES=cluster -t tokenfuse:cluster .

# ---- build stage ----------------------------------------------------------
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
ARG FEATURES=""
RUN if [ -n "$FEATURES" ]; then \
        cargo build --release -p tokenfuse-gateway --features "$FEATURES"; \
    else \
        cargo build --release -p tokenfuse-gateway; \
    fi \
    && strip target/release/tokenfuse

# ---- runtime stage --------------------------------------------------------
FROM debian:bookworm-slim
# CA roots for talking to real HTTPS providers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 tokenfuse
COPY --from=build /src/target/release/tokenfuse /usr/local/bin/tokenfuse
# A writable data dir owned by the non-root user. When you mount a fresh named
# volume at /data, Docker copies this ownership onto it, so durable raft storage
# (TOKENFUSE_CLUSTER_DATA_DIR=/data) works without running as root.
RUN mkdir -p /data && chown tokenfuse:tokenfuse /data
VOLUME /data
USER tokenfuse
# Bind on all interfaces inside the container; map the port when you run it.
ENV TOKENFUSE_ADDR=0.0.0.0:4100
EXPOSE 4100
ENTRYPOINT ["tokenfuse"]
