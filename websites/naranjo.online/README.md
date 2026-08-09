# naranjo.online — Go + Svelte

The production path is a Svelte build embedded into a dependency-free Go HTTP
binary and packaged in a shell-less distroless image. The current frontend
contract is `Hello World!`; the service also exposes `/livez` and `/readyz`.

Small version-controlled UI material belongs under `frontend/src/assets/` in
the documented image, audio, video, icon, font, or texture category. Each file
must stay below the repository's small-asset ceiling. Components build logical
URLs with `src/lib/media.ts`; they never know a Pi path, volume, or origin.

Heavy images, FLAC, source video, and delivery derivatives never enter this
tree, the Svelte output, Go embed, OCI build context, Flux, a ConfigMap, a Secret,
or etcd. The Go service has focused tests for bounded regular-file streaming,
HEAD/Range/conditionals, MIME, cache classes, traversal, symlinks, missing files,
and overload. Production still sets `MEDIA_ENABLED=false`, renders no volume,
and the chart schema rejects enablement until ADR 0012's Pi/storage/backup/load
evidence exists. Current Cloudflare self-serve terms also make deliberate
large-media delivery a zero-spend `NO-GO`, independent of local code readiness.

`frontend/package-lock.json` was generated with the exact Node 24.19.0/npm
11.17.0 pins. `npm ci`, Svelte checks/build, Go 1.26.5 tests/vet/build, and a
local HTTP/security-header smoke test pass. The container build and multi-arch
publication still require the pinned CI builder. Until a reviewed published
image digest exists, the HelmRelease remains suspended and the all-zero digest
sentinel blocks deployment readiness.

Python is not in this application or image. Repository-level Python checks exist
only because they provide dependency-free policy/redaction on the current
workstation.
