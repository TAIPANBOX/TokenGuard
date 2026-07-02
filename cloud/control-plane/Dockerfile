# TokenFuse Cloud control plane — a single static Go binary (embedded dashboard).
# Build context is this directory: docker build cloud/control-plane
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/control-plane . \
    && mkdir -p /data-empty

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/control-plane /control-plane
# A /data dir owned by the non-root user (65532), so a mounted volume for
# TOKENFUSE_CLOUD_DATA is writable (Docker copies this ownership onto a fresh
# named volume).
COPY --from=build --chown=65532:65532 /data-empty /data
EXPOSE 8080
ENTRYPOINT ["/control-plane"]
