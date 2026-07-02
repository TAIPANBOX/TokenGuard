# TokenFuse Cloud control plane — a single static Go binary (embedded dashboard).
# Build context is this directory: docker build cloud/control-plane
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/control-plane .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/control-plane /control-plane
EXPOSE 8080
ENTRYPOINT ["/control-plane"]
