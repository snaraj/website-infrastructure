# Build the browser bundle in a pinned stage so npm and its dependency graph
# never enter the runtime image.
FROM docker.io/library/node:24.19.0-trixie-slim@sha256:0711b541c1c33a8a530ac4f0d391baa9a15b3d804695b1b24a47daa5fb60e74d AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run check && npm run build

# Compile and test a static Go binary for both amd64 CI and arm64 production;
# Buildx selects the matching architecture from this manifest-list pin.
FROM docker.io/library/golang:1.26.5-trixie@sha256:87ffdb09b6a2e29ff910748b745395e8a0299aa80b7c0551cdca9b55e3fd2b3e AS backend
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=frontend /src/internal/web/dist/ ./internal/web/dist/
RUN go test ./... && \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/lidersea-com ./cmd/server

# The final shell-less, non-root image contains only the independently
# promotable site binary and no compilers, package managers, or source tree.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
COPY --from=backend --chown=65532:65532 /out/lidersea-com /lidersea-com
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/lidersea-com"]
