# lidersea.com — Go + Svelte

This intentionally small launch site is a Svelte build embedded into a
dependency-free Go HTTP binary and packaged in a shell-less distroless image.
Both the raw HTML fallback and hydrated page say `Hello World!` and `Website
coming soon!`; the origin also exposes read-only `/livez` and `/readyz` probes.
Keeping the second site self-contained gives `lidersea.com` its own image,
release identity, rollback boundary, and production checks without coupling it
to changes for `naranjo.online`.

The Node, npm, Go, builder, and runtime versions are exact repository pins. Run
the Svelte check/build before Go tests so the production bundle exists at the
embed boundary. Publication produces and verifies one amd64/arm64 OCI graph,
but the all-zero chart digest and `deploymentReady: false` deliberately keep
deployment blocked until a reviewed digest is promoted and the separate Flux
release is explicitly unsuspended.

Python is not in this application or image. Repository-level Python remains
limited to dependency-free local policy and redaction checks.
