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

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  input.metadata.name in release_kustomizations
  object.get(input.spec, "suspend", false) == true
  msg := sprintf("Kustomization %s remains suspended", [input.metadata.name])
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

deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace == "cloudflare-public"
  input.metadata.name == "cloudflared"
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
