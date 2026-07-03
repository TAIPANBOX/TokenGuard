# TokenFuse Cloud control plane — portable container image (Rust).
#
# Build context is the workspace root (the crate is a workspace member):
#
#   docker build -f crates/cloud/Dockerfile -t tokenfuse-control-plane .
#   docker run -p 8080:8080 ghcr.io/taipanbox/tokenfuse-control-plane
#
# Published to GHCR by .github/workflows/release.yml. Successor to the original
# Go control plane (docs/02-architecture.md, ADR-7).

# ---- build stage ----------------------------------------------------------
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p tokenfuse-cloud \
    && strip target/release/tokenfuse-cloud

# ---- runtime stage --------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 tokenfuse
COPY --from=build /src/target/release/tokenfuse-cloud /usr/local/bin/tokenfuse-cloud
# A writable data dir owned by the non-root user. When a fresh named volume is
# mounted at /data, Docker copies this ownership onto it, so the durable JSON
# snapshot (TOKENFUSE_CLOUD_DATA=/data/state.json) is writable without root.
RUN mkdir -p /data && chown tokenfuse:tokenfuse /data
VOLUME /data
USER tokenfuse
EXPOSE 8080
ENTRYPOINT ["tokenfuse-cloud"]
