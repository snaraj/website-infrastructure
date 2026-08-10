# ADR 0010: Go service, Svelte frontend, and Helm packaging

- Status: Accepted
- Date: 2026-08-08

## Decision

Build the `naranjo.online` and `lidersea.com` frontends with Svelte. Compile
each site's static assets and embed them into its own Go HTTP service. Package
each workload as an independent Helm chart and reconcile it with Flux's Helm
controller. Keep Kustomize for bootstrap, namespaces, RBAC, NetworkPolicy
composition, and HelmRelease definitions.

Both services expose the compiled site plus `/livez` and `/readyz`.
`naranjo.online` additionally contains a discovery-gated, read-only static media
handler described by ADR 0012; its chart cannot mount or enable media today.
That handler is not an upload or application API. Any API, identity, session,
database, background job, runtime transcoder, or writable data surface reopens
the threat model.

## Rationale

Go produces small static ARM64/amd64 binaries, has a strong standard HTTP/test
stack, and aligns with Kubernetes/Cloud Native tooling. Svelte keeps the initial
frontend small while preserving a component model for later work. Helm gives the
workload an explicit, testable values contract without adding an ingress layer.

The sites may reuse validation tooling, but images, workflows, digests, charts,
and promotion remain independent so one release cannot silently move the other.

Using SOPS/age or Kubernetes does not by itself require application code to be
Go; this is a maintainability and runtime choice, not a security shortcut.

## Python boundary

Python is permitted only for dependency-free repository policy tests and output
redaction when it is available in the local validation environment. Python is
absent from the production image and application request path.

## Consequences

Flux must include helm-controller, CI must test Go/Svelte/Helm independently,
and the container build has separate Node, Go, and minimal runtime stages. All
tool/action/base-image versions and the final application digest remain pinned.

## Amendment (2026-08-10)

The decision stands unchanged; only its location moved. The Go/Svelte/Helm
sources now live in the standalone repositories `snaraj/naranjo.online` and
`snaraj/lidersea.com`, extracted with full history. This platform repository
consumes their signed images and OCI charts by digest.
