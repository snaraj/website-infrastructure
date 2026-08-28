package main

import rego.v1

site_namespaces := {"naranjo-online", "lidersea-com"}

release_kustomizations := {"platform-services", "naranjo-online", "lidersea-com"}

valid_reviewed_capacity_quota if {
  input.metadata.name == "namespace-budget"
  annotations := object.get(input.metadata, "annotations", {})
  object.get(annotations, "platform.snaraj.dev/readiness", "") == "reviewed-pi-capacity"
  object.get(annotations, "platform.snaraj.dev/capacity-evidence-sha256", "") == "955a59cbf5ba0bd36f5e62349ed070a2b1eba6fb3ef072951435010edcceaf34"
  object.get(input.spec, "hard", {}) == {
    "pods": "6",
    "requests.cpu": "150m",
    "requests.memory": "192Mi",
    "limits.cpu": "1200m",
    "limits.memory": "768Mi",
  }
}

deny contains msg if {
  input.kind == "HelmRelease"
  object.get(input.spec, "suspend", false) == true
  msg := sprintf("HelmRelease %s remains suspended", [input.metadata.name])
}

# Release-mode half of the digest-selected sync contract. The scaffold renderer
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

# The verified exact-site chart is the sole workload image-identity carrier.
# Platform values are closed to one literal readiness scalar; missing, false,
# malformed, image-bearing, or otherwise extra values all take this same arm.
valid_site_release_values if {
  spec := object.get(input, "spec", null)
  is_object(spec)
  object.get(spec, "values", null) == {"deploymentReady": true}
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.metadata.namespace in site_namespaces
  not valid_site_release_values
  msg := sprintf("HelmRelease %s values must contain exactly deploymentReady: true", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace in {"naranjo-online", "lidersea-com"}
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
