# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM ghcr.io/sigstore/cosign/cosign:58aae9e112fa1de80594eed34667e920ac4d4a3b@sha256:5221922dc57a6717b0aa700692bd22ffb10e7e94d1d991958c6f9ae460b262e5 AS cosign
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.0-trixie@sha256:ae28539d2ef595b9a2930dd7f031d9592376829dc0eae7cb869559f7d5812c3a AS build

ARG TARGETARCH
ARG TARGETOS
WORKDIR /src
COPY go.mod ./
COPY internal/releaseselector/ ./internal/releaseselector/
COPY cmd/platform-release-selector/main.go ./cmd/platform-release-selector/main.go
RUN --network=none go test ./...
RUN --network=none CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -buildvcs=false -trimpath -ldflags='-s -w' \
    -o /out/platform-release-selector ./cmd/platform-release-selector

FROM build AS trusted-root
COPY cmd/platform-release-selector/trusted_root.json /trusted_root.json
RUN printf '%s  %s\n' \
    '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66' \
    '/trusted_root.json' | sha256sum -c -

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
COPY --from=build --chown=65532:65532 /out/platform-release-selector /platform-release-selector
COPY --from=cosign --chmod=0555 /ko-app/cosign /usr/local/bin/cosign
COPY --from=trusted-root --chmod=0444 /trusted_root.json /usr/local/share/sigstore/trusted_root.json
USER 65532:65532
ENTRYPOINT ["/platform-release-selector"]
