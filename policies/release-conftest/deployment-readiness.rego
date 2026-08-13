package main

import rego.v1

site_namespaces := {"naranjo-online", "lidersea-com"}

release_kustomizations := {"admission", "platform-services", "naranjo-online", "lidersea-com"}

core_admission_policies := {
  "require-restricted-workloads",
  "disallow-public-services",
  "require-approved-images",
  "disallow-undiscovered-storage",
  "disallow-tenant-media-payloads",
  "require-zero-site-capacity",
  "require-exact-tenant-networking",
  "require-release-readiness",
}

signature_policies := {
  "require-signed-naranjo-online",
  "require-signed-lidersea-com",
}

valid_reviewed_capacity_quota if {
  input.metadata.name == "namespace-budget"
  annotations := object.get(input.metadata, "annotations", {})
  object.get(annotations, "platform.snaraj.dev/readiness", "") == "reviewed-pi-capacity"
  regex.match("^[0-9a-f]{64}$", object.get(annotations, "platform.snaraj.dev/capacity-evidence-sha256", ""))
  hard := object.get(input.spec, "hard", {})
  object.keys(hard) == {"pods", "requests.cpu", "requests.memory", "limits.cpu", "limits.memory"}
  to_number(hard.pods) >= 2
  every key in {"requests.cpu", "requests.memory", "limits.cpu", "limits.memory"} {
    regex.match("^[1-9][0-9]*(?:m|Ki|Mi|Gi)?$", hard[key])
  }
}

deny contains msg if {
  input.kind == "HelmRelease"
  object.get(input.spec, "suspend", false) == true
  msg := sprintf("HelmRelease %s remains suspended", [input.metadata.name])
}

# Release-mode half of the tag-driven sync contract. The scaffold renderer
# already denies an unverified chart source structurally; this rule makes the
# same denial part of what a promoted or active render must survive, so a
# release can never ship a site whose chart would be accepted unsigned.
deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in site_namespaces
  object.get(object.get(input.spec, "verify", {}), "provider", "") != "cosign"
  msg := sprintf("chart source %s/%s does not require cosign verification", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in site_namespaces
  count(object.get(object.get(input.spec, "verify", {}), "matchOIDCIdentity", [])) != 1
  msg := sprintf("chart source %s/%s does not bind exactly one keyless publisher identity", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  input.metadata.name in release_kustomizations
  object.get(input.spec, "suspend", false) == true
  msg := sprintf("Kustomization %s remains suspended", [input.metadata.name])
}

# Each site's chart renders in its own repository, so the reviewed desired
# state this repository still owns for a site is its HelmRelease: the readiness
# flag and image digest handed to that chart. These three rules are the
# release-grade counterparts of the chart-level readiness/digest denials below,
# applied to the only layer this gate can render, so a promoted site is proven
# from the artifact that exists here instead of one that no longer does.
deny contains msg if {
  input.kind == "HelmRelease"
  input.metadata.namespace in site_namespaces
  object.get(object.get(input.spec, "values", {}), "deploymentReady", false) != true
  msg := sprintf("HelmRelease %s is not marked ready", [input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.metadata.namespace in site_namespaces
  site_image_digest == "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  msg := sprintf("HelmRelease %s still names the all-zero image digest", [input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.metadata.namespace in site_namespaces
  not regex.match("^sha256:[0-9a-f]{64}$", site_image_digest)
  msg := sprintf("HelmRelease %s does not name a canonical image digest", [input.metadata.name])
}

# The release TAG is the human half of the same identity and is gated exactly
# like the digest: a released site must have advanced off the v0.0.0 sentinel
# and must name one canonical SemVer release. Two arms, not one, so a sentinel
# tag and a malformed tag are distinguishable in the denial output — the
# renderer's closed denial vocabulary asserts each by message.
deny contains msg if {
  input.kind == "HelmRelease"
  input.metadata.namespace in site_namespaces
  site_image_tag == "v0.0.0"
  msg := sprintf("HelmRelease %s still names the sentinel release tag", [input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.metadata.namespace in site_namespaces
  not regex.match("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$", site_image_tag)
  msg := sprintf("HelmRelease %s does not name a canonical release tag", [input.metadata.name])
}

# Rego's object.get raises a builtin type error on a non-object receiver, and
# under OPA's default non-strict mode that error makes the ENCLOSING deny body
# undefined — the rule silently does not fire. A nested `object.get` chain is
# therefore fail-open on a degenerate `spec`, `values`, or `image` value. Every
# level below is guarded, and a degenerate shape is denied by its own arm
# instead of skipped.
site_image_mapping := image if {
  spec := input.spec
  is_object(spec)
  values := object.get(spec, "values", {})
  is_object(values)
  image := object.get(values, "image", {})
  is_object(image)
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.metadata.namespace in site_namespaces
  not site_image_mapping
  msg := sprintf("HelmRelease %s does not state a well-formed image mapping", [input.metadata.name])
}

site_image_digest := digest if {
  digest := object.get(site_image_mapping, "digest", "")
  is_string(digest)
}

site_image_tag := tag if {
  tag := object.get(site_image_mapping, "tag", "")
  is_string(tag)
}

deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace in {"naranjo-online", "lidersea-com", "kyverno"}
  object.get(object.get(input.metadata, "annotations", {}), "platform.snaraj.dev/deployment-ready", "") != "true"
  msg := sprintf("Deployment %s is not marked ready", [input.metadata.name])
}

deny contains msg if {
  input.kind == "ReplicaSet"
  input.metadata.namespace in {"cloudflare-public", "naranjo-online", "lidersea-com"}
  msg := sprintf("raw tenant ReplicaSet %s/%s is forbidden in reviewed desired state", [input.metadata.namespace, input.metadata.name])
}

# Each per-site connector Deployment (naranjo-online-tunnel, lidersea-com-tunnel)
# must carry a resolved tunnel-token revision; an unresolved revision on EITHER
# connector keeps the connector desired state fail-closed.
cloudflared_connector_deployments := {"naranjo-online-tunnel", "lidersea-com-tunnel"}

deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace == "cloudflare-public"
  input.metadata.name in cloudflared_connector_deployments
  revision := object.get(
    object.get(object.get(object.get(input.spec, "template", {}), "metadata", {}), "annotations", {}),
    "platform.snaraj.dev/tunnel-token-revision",
    "not-configured",
  )
  revision in {"", "not-configured", "UNRESOLVED"}
  msg := "cloudflared tunnel token revision remains unresolved"
}

deny contains msg if {
  input.kind == "Deployment"
  some container in input.spec.template.spec.containers
  endswith(container.image, "@sha256:0000000000000000000000000000000000000000000000000000000000000000")
  msg := sprintf("container %s still uses the all-zero digest", [container.name])
}

deny contains msg if {
  input.kind == "ResourceQuota"
  input.metadata.namespace in site_namespaces
  not valid_reviewed_capacity_quota
  msg := sprintf("site capacity gate remains closed or lacks a hash-bound reviewed budget in namespace %s", [input.metadata.namespace])
}

deny contains msg if {
  input.kind == "ClusterPolicy"
  input.metadata.name in core_admission_policies
  object.get(input.spec, "validationFailureAction", "Audit") != "Enforce"
  msg := sprintf("core admission policy %s is not enforced", [input.metadata.name])
}

deny contains msg if {
  input.kind == "ClusterPolicy"
  input.metadata.name in core_admission_policies
  object.get(object.get(input.spec, "webhookConfiguration", {}), "failurePolicy", "") != "Fail"
  msg := sprintf("core admission policy %s does not fail closed", [input.metadata.name])
}

deny contains msg if {
  input.kind == "ClusterPolicy"
  input.metadata.name in signature_policies
  object.get(input.spec, "validationFailureAction", "Audit") != "Enforce"
  msg := sprintf("signature admission policy %s is not enforced", [input.metadata.name])
}
