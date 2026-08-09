# Build only the small, version-controlled Svelte UI in a pinned stage. The
# repository media gate prevents heavy delivery assets from entering this context.
FROM docker.io/library/node:24.19.0-trixie-slim@sha256:0711b541c1c33a8a530ac4f0d391baa9a15b3d804695b1b24a47daa5fb60e74d AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run check && npm test && npm run build

# Test and compile one static binary for CI amd64 and Pi arm64; any future media
# remains a runtime read-only mount and never becomes part of this Go embed.
FROM docker.io/library/golang:1.26.5-trixie@sha256:87ffdb09b6a2e29ff910748b745395e8a0299aa80b7c0551cdca9b55e3fd2b3e AS backend
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=frontend /src/internal/web/dist/ ./internal/web/dist/
RUN go test ./... && \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/naranjo-online ./cmd/server

# The final shell-less image contains only the independently promotable origin
# binary, with no package manager, source tree, compiler, Python, or media bytes.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
COPY --from=backend --chown=65532:65532 /out/naranjo-online /naranjo-online
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/naranjo-online"]
