package main

import rego.v1

workload_kinds := {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}

tenant_namespaces := {"cloudflare-public", "naranjo-online", "lidersea-com"}

restricted_role_namespaces := {"cloudflare-public", "naranjo-online", "lidersea-com", "kyverno"}

site_namespaces := {"naranjo-online", "lidersea-com"}

gateway_kinds := {
  "GatewayClass",
  "Gateway",
  "HTTPRoute",
  "GRPCRoute",
  "TCPRoute",
  "TLSRoute",
  "UDPRoute",
  "ReferenceGrant",
}

undiscovered_storage_kinds := {
  "PersistentVolume",
  "PersistentVolumeClaim",
  "StorageClass",
  "CSIDriver",
}

undiscovered_pod_volume_sources := {
  "persistentVolumeClaim",
  "ephemeral",
  "csi",
  "nfs",
  "iscsi",
  "cephfs",
  "rbd",
  "fc",
  "flexVolume",
  "glusterfs",
}

etcd_payload_fields := {"data", "binaryData", "stringData"}

media_payload_key_pattern := `(?i).*[.](?:avif|bmp|flac|gif|ico|jpe?g|m4a|mkv|mov|mp3|mp4|ogg|opus|pdf|png|svg|tiff?|wav|webm|webp|woff2?|zip)$`

encoded_media_prefix_pattern := `^(?:iVBORw0KGgo|/9j/|R0lGOD|UklGR|JVBERi0|SUQz|T2dnUw|ZkxhQw|UEsDB)`

is_workload if {
  input.kind in workload_kinds
}

pod_spec := input.spec if {
  input.kind == "Pod"
}

pod_spec := input.spec.jobTemplate.spec.template.spec if {
  input.kind == "CronJob"
}

pod_spec := input.spec.template.spec if {
  input.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
}

# The Pod-level metadata that carries the workload identity labels. Volume
# admission needs it because a connector's mounted Secret must be bound to that
# connector's own instance, not merely to the set of known token names.
pod_metadata := object.get(input, "metadata", {}) if {
  input.kind == "Pod"
}

pod_metadata := object.get(input.spec.jobTemplate.spec.template, "metadata", {}) if {
  input.kind == "CronJob"
}

pod_metadata := object.get(input.spec.template, "metadata", {}) if {
  input.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
}

# The site connector identity this Pod claims (empty when absent).
connector_instance := object.get(
  object.get(pod_metadata, "labels", {}),
  "app.kubernetes.io/instance",
  "",
)

restricted_namespace if {
  object.get(object.get(input, "metadata", {}), "namespace", "default") in tenant_namespaces
}

regular_and_init_containers := array.concat(
  object.get(pod_spec, "initContainers", []),
  object.get(pod_spec, "containers", []),
) if {
  is_workload
}

containers := array.concat(
  regular_and_init_containers,
  object.get(pod_spec, "ephemeralContainers", []),
) if {
  is_workload
}

approved_kustomization_accounts := {
  "flux-system": "root-reconciler",
  "platform-prerequisites": "platform-prerequisites-reconciler",
  "admission": "admission-reconciler",
  "platform-services": "platform-services-reconciler",
  "naranjo-online": "naranjo-online-reconciler",
  "lidersea-com": "lidersea-com-reconciler",
}

approved_kustomization_paths := {
  "flux-system": "./kubernetes/reconciliation",
  "platform-prerequisites": "./kubernetes/platform/prerequisites",
  "admission": "./kubernetes/platform/admission",
  "platform-services": "./kubernetes/platform/cloudflare-public/release",
  "naranjo-online": "./kubernetes/websites/naranjo-online",
  "lidersea-com": "./kubernetes/websites/lidersea-com",
}

approved_kustomization_dependencies := {
  "flux-system": set(),
  "platform-prerequisites": set(),
  "admission": {"platform-prerequisites"},
  "platform-services": {"platform-prerequisites", "admission"},
  "naranjo-online": {"platform-prerequisites", "admission", "platform-services"},
  "lidersea-com": {"platform-prerequisites", "admission", "platform-services"},
}

site_workload_accounts := {
  "naranjo-online": "naranjo-online",
  "lidersea-com": "lidersea-com",
}

tenant_source_names := {
  "cloudflare-public": "cloudflare-public-source",
  "naranjo-online": "naranjo-online-source",
  "lidersea-com": "lidersea-com-source",
}

tenant_chart_paths := {
  "cloudflare-public": "./kubernetes/platform/cloudflare-public/chart",
  "naranjo-online": "./chart",
  "lidersea-com": "./chart",
}

approved_git_source_scopes := {
  "flux-system/flux-system": {
    "ignore": "/*\n!/kubernetes\n!/policies\n",
    "sparseCheckout": ["kubernetes", "policies"],
  },
  "cloudflare-public/cloudflare-public-source": {
    "ignore": "/*\n!/kubernetes\n/kubernetes/*\n!/kubernetes/platform\n/kubernetes/platform/*\n!/kubernetes/platform/cloudflare-public\n/kubernetes/platform/cloudflare-public/*\n!/kubernetes/platform/cloudflare-public/chart\n",
    "sparseCheckout": ["kubernetes/platform/cloudflare-public/chart"],
  },
  "naranjo-online/naranjo-online-source": {
    "ignore": "/*\n!/chart\n",
    "sparseCheckout": ["chart"],
  },
  "lidersea-com/lidersea-com-source": {
    "ignore": "/*\n!/chart\n",
    "sparseCheckout": ["chart"],
  },
}

# Each tenant source pulls its own standalone public repository; the
# platform sources keep pulling this repository.
approved_git_source_urls := {
  "flux-system/flux-system": "https://github.com/snaraj/website-infrastructure.git",
  "cloudflare-public/cloudflare-public-source": "https://github.com/snaraj/website-infrastructure.git",
  "naranjo-online/naranjo-online-source": "https://github.com/snaraj/naranjo.online.git",
  "lidersea-com/lidersea-com-source": "https://github.com/snaraj/lidersea.com.git",
}

valid_site_ingress_policy if {
  namespace := input.metadata.namespace
  namespace in site_namespaces
  input.metadata.name == sprintf("cloudflared-to-%s", [namespace])

  selector_labels := object.get(object.get(input.spec, "podSelector", {}), "matchLabels", {})
  selector_labels == {
    "app.kubernetes.io/name": namespace,
    "app.kubernetes.io/instance": namespace,
  }

  ingress := object.get(input.spec, "ingress", [])
  count(ingress) == 1
  rule := ingress[0]
  peers := object.get(rule, "from", [])
  count(peers) == 1
  peer := peers[0]
  # Symmetry with the connector-egress side: the ingress peer pins BOTH the
  # shared platform name AND this site's own connector instance
  # (<site>-tunnel), so only that site's connector — never the other site's —
  # can open the TCP 8080 origin leg even if a future additive egress policy
  # widened the connector side.
  peer == {
    "namespaceSelector": {
      "matchLabels": {"kubernetes.io/metadata.name": "cloudflare-public"},
    },
    "podSelector": {
      "matchLabels": {
        "app.kubernetes.io/name": "cloudflare-public",
        "app.kubernetes.io/instance": sprintf("%s-tunnel", [namespace]),
      },
    },
  }
  object.get(rule, "ports", []) == [{"port": 8080, "protocol": "TCP"}]
  count(object.get(input.spec, "egress", [])) == 0
}

valid_default_deny_policy if {
  input.metadata.name == "default-deny"
  object.get(input.spec, "podSelector", null) == {}
  {policy_type | some policy_type in object.get(input.spec, "policyTypes", [])} == {"Ingress", "Egress"}
  count(object.get(input.spec, "ingress", [])) == 0
  count(object.get(input.spec, "egress", [])) == 0
}

valid_public_dns_rule(rule) if {
  object.get(rule, "to", []) == [{
    "namespaceSelector": {
      "matchLabels": {"kubernetes.io/metadata.name": "kube-system"},
    },
    "podSelector": {
      "matchLabels": {"k8s-app": "kube-dns"},
    },
  }]
  {port | some port in object.get(rule, "ports", [])} == {
    {"port": 53, "protocol": "TCP"},
    {"port": 53, "protocol": "UDP"},
  }
}

valid_public_site_rule(rule) if {
  peers := object.get(rule, "to", [])
  count(peers) == 1
  peer := peers[0]
  namespace := object.get(
    object.get(object.get(peer, "namespaceSelector", {}), "matchLabels", {}),
    "kubernetes.io/metadata.name",
    "",
  )
  namespace in site_namespaces
  peer == {
    "namespaceSelector": {
      "matchLabels": {"kubernetes.io/metadata.name": namespace},
    },
    "podSelector": {
      "matchLabels": {"app.kubernetes.io/name": namespace},
    },
  }
  object.get(rule, "ports", []) == [{"port": 8080, "protocol": "TCP"}]
}

valid_public_edge_rule(rule) if {
  peers := object.get(rule, "to", [])
  count(peers) == 1
  peer := peers[0]
  ip_block := object.get(peer, "ipBlock", {})
  object.keys(peer) == {"ipBlock"}
  object.get(ip_block, "cidr", "") == "0.0.0.0/0"
  {cidr | some cidr in object.get(ip_block, "except", [])} == {
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
  }
  {port | some port in object.get(rule, "ports", [])} == {
    {"port": 7844, "protocol": "TCP"},
    {"port": 7844, "protocol": "UDP"},
  }
}

# The egress-policy envelope every cloudflare-public tunnel policy shares:
# egress-only, no ingress, exactly one egress rule.
valid_public_policy_envelope if {
  {policy_type | some policy_type in object.get(input.spec, "policyTypes", [])} == {"Egress"}
  count(object.get(input.spec, "ingress", [])) == 0
  count(object.get(input.spec, "egress", [])) == 1
}

# DNS and edge are identical for every connector, so they carry the shared
# name-only selector that reaches both site connectors' Pods (size 1).
valid_public_shared_selector if {
  object.get(object.get(input.spec, "podSelector", {}), "matchLabels", {}) == {
    "app.kubernetes.io/name": "cloudflare-public",
  }
}

# A site connector-egress policy is pinned to exactly one connector by
# name+instance (<site>-tunnel) — the egress half of the double-pin (size 2).
valid_public_connector_selector(instance) if {
  object.get(object.get(input.spec, "podSelector", {}), "matchLabels", {}) == {
    "app.kubernetes.io/name": "cloudflare-public",
    "app.kubernetes.io/instance": instance,
  }
}

valid_public_tunnel_policy if {
  valid_public_policy_envelope
  valid_public_shared_selector
  input.metadata.name == "cloudflared-dns"
  valid_public_dns_rule(input.spec.egress[0])
}

valid_public_tunnel_policy if {
  valid_public_policy_envelope
  valid_public_shared_selector
  input.metadata.name == "cloudflared-edge"
  valid_public_edge_rule(input.spec.egress[0])
}

valid_public_tunnel_policy if {
  valid_public_policy_envelope
  namespace := trim_prefix(input.metadata.name, "cloudflared-")
  namespace in site_namespaces
  valid_public_connector_selector(sprintf("%s-tunnel", [namespace]))
  valid_public_site_rule(input.spec.egress[0])
  target := input.spec.egress[0].to[0].namespaceSelector.matchLabels["kubernetes.io/metadata.name"]
  target == namespace
}

valid_zero_capacity_quota if {
  input.metadata.name == "capacity-not-ready"
  object.get(object.get(input.metadata, "annotations", {}), "platform.snaraj.dev/readiness", "") == "blocked-until-pi-capacity-evidence"
  object.get(input.spec, "hard", {}) == {"pods": "0"}
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

valid_tenant_volume(namespace, volume) if {
  namespace in site_namespaces
  volume == {
    "name": "tmp",
    "emptyDir": {
      "medium": "Memory",
      "sizeLimit": "16Mi",
    },
  }
}

# Each connector mounts ONLY ITS OWN site's tunnel-token Secret: the expected
# name is DERIVED from the connector's own instance label (<site>-tunnel ->
# <site>-tunnel-token), so a connector mounting the other site's token is
# denied even though that token is otherwise a known, approved Secret. Merely
# allowlisting the two names would let either connector mount either token and
# break ADR 0015's per-site identity tuple. The superseded shared
# pi-websites-tunnel-token matches no connector instance and is denied.
valid_tenant_volume(namespace, volume) if {
  namespace == "cloudflare-public"
  connector_instance in {"naranjo-online-tunnel", "lidersea-com-tunnel"}
  volume == {
    "name": "tunnel-token",
    "secret": {
      "defaultMode": 288,
      "items": [{"key": "token", "path": "token"}],
      "secretName": sprintf("%s-token", [connector_instance]),
    },
  }
}

valid_source_controller_storage if {
  containers := object.get(input.spec.template.spec, "containers", [])
  count(containers) == 1
  manager := containers[0]
  manager.name == "manager"
  resources := object.get(manager, "resources", {})
  object.get(object.get(resources, "requests", {}), "ephemeral-storage", "") == "128Mi"
  object.get(object.get(resources, "limits", {}), "ephemeral-storage", "") == "1Gi"
  "--no-cross-namespace-refs=true" in object.get(manager, "args", [])

  volumes := object.get(input.spec.template.spec, "volumes", [])
  count(volumes) == 2
  some data_volume in volumes
  data_volume == {"name": "data", "emptyDir": {"sizeLimit": "768Mi"}}
  some tmp in volumes
  tmp == {"name": "tmp", "emptyDir": {"sizeLimit": "128Mi"}}
}

deny contains msg if {
  input.kind == "Service"
  object.get(input.spec, "type", "ClusterIP") != "ClusterIP"
  msg := sprintf("Service %s must be ClusterIP", [input.metadata.name])
}

deny contains msg if {
  input.kind == "ReplicaSet"
  input.metadata.namespace in tenant_namespaces
  msg := sprintf("raw tenant ReplicaSet %s/%s is forbidden; only an exact Deployment may own replicas", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "Role"
  input.metadata.namespace in restricted_role_namespaces
  some rule in object.get(input, "rules", [])
  some resource in object.get(rule, "resources", [])
  resource in {"pods", "pods/exec", "replicasets", "daemonsets", "statefulsets", "jobs", "cronjobs"}
  msg := sprintf("Role %s/%s must not grant direct %s workload control", [input.metadata.namespace, input.metadata.name, resource])
}

deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace == "flux-system"
  input.metadata.name == "source-controller"
  not valid_source_controller_storage
  msg := "source-controller must bound /data and /tmp plus container ephemeral-storage and cross-namespace references"
}

deny contains msg if {
  input.kind == "Ingress"
  msg := sprintf("Ingress %s is forbidden; Cloudflare Tunnel routes directly to ClusterIP Services", [input.metadata.name])
}

deny contains msg if {
  input.kind in gateway_kinds
  msg := sprintf("Gateway API resource %s/%s is forbidden before an approved routing redesign", [input.kind, input.metadata.name])
}

deny contains msg if {
  input.kind == "Service"
  count(object.get(input.spec, "externalIPs", [])) > 0
  msg := sprintf("Service %s must not declare externalIPs", [input.metadata.name])
}

deny contains msg if {
  is_workload
  object.get(pod_spec, "hostNetwork", false)
  msg := sprintf("%s %s must not use hostNetwork", [input.kind, input.metadata.name])
}

deny contains msg if {
  is_workload
  object.get(pod_spec, "hostPID", false)
  msg := sprintf("%s %s must not use hostPID", [input.kind, input.metadata.name])
}

deny contains msg if {
  is_workload
  object.get(pod_spec, "hostIPC", false)
  msg := sprintf("%s %s must not use hostIPC", [input.kind, input.metadata.name])
}

deny contains msg if {
  is_workload
  restricted_namespace
  object.get(pod_spec, "automountServiceAccountToken", true) != false
  msg := sprintf("%s %s must disable ServiceAccount token automount", [input.kind, input.metadata.name])
}

deny contains msg if {
  input.kind == "ServiceAccount"
  restricted_namespace
  object.get(input, "automountServiceAccountToken", true) != false
  msg := sprintf("ServiceAccount %s must disable token automount", [input.metadata.name])
}

deny contains msg if {
  is_workload
  restricted_namespace
  namespace := input.metadata.namespace
  expected := object.union(site_workload_accounts, {"cloudflare-public": "cloudflared"})[namespace]
  object.get(pod_spec, "serviceAccountName", "") != expected
  msg := sprintf("%s %s must use only ServiceAccount %s", [input.kind, input.metadata.name, expected])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  source_namespace := object.get(object.get(input.spec, "sourceRef", {}), "namespace", "flux-system")
  source_namespace != "flux-system"
  msg := sprintf("Kustomization %s must not reference a source outside flux-system", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  input.metadata.namespace != "flux-system"
  msg := sprintf("Kustomization %s must live in flux-system", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  expected_path := object.get(approved_kustomization_paths, input.metadata.name, "")
  expected_path != ""
  object.get(input.spec, "path", "") != expected_path
  msg := sprintf("Kustomization %s must use path %s", [input.metadata.name, expected_path])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  source_ref := object.get(input.spec, "sourceRef", {})
  object.get(source_ref, "kind", "") != "GitRepository"
  msg := sprintf("Kustomization %s must use the root GitRepository", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  source_ref := object.get(input.spec, "sourceRef", {})
  object.get(source_ref, "name", "") != "flux-system"
  msg := sprintf("Kustomization %s must use source flux-system", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  input.metadata.name in {"platform-prerequisites", "admission"}
  object.get(input.spec, "wait", false) != true
  msg := sprintf("Kustomization %s must wait for runtime readiness", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  expected := object.get(approved_kustomization_dependencies, input.metadata.name, set())
  actual := {dependency.name | some dependency in object.get(input.spec, "dependsOn", [])}
  actual != expected
  msg := sprintf("Kustomization %s must use exact dependencies %v", [input.metadata.name, expected])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  source_ref := object.get(object.get(object.get(input.spec, "chart", {}), "spec", {}), "sourceRef", {})
  source_namespace := object.get(source_ref, "namespace", input.metadata.namespace)
  source_namespace != input.metadata.namespace
  msg := sprintf("HelmRelease %s must not reference a cross-namespace source", [input.metadata.name])
}

deny contains msg if {
  input.kind in {"GitRepository", "HelmRepository", "OCIRepository"}
  object.get(input.spec, "secretRef", null) != null
  msg := sprintf("%s %s must use anonymous public source access", [input.kind, input.metadata.name])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  input.metadata.namespace in tenant_namespaces
  expected_name := tenant_source_names[input.metadata.namespace]
  input.metadata.name != expected_name
  msg := sprintf("GitRepository %s/%s must use canonical identity %s", [input.metadata.namespace, input.metadata.name, expected_name])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  key := sprintf("%s/%s", [input.metadata.namespace, input.metadata.name])
  not key in object.keys(approved_git_source_scopes)
  msg := sprintf("GitRepository %s is outside the exact source identity allowlist", [key])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  key := sprintf("%s/%s", [input.metadata.namespace, input.metadata.name])
  expected := object.get(approved_git_source_scopes, key, null)
  expected != null
  object.get(input.spec, "sparseCheckout", []) != expected.sparseCheckout
  msg := sprintf("GitRepository %s must sparse-checkout only %v", [key, expected.sparseCheckout])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  key := sprintf("%s/%s", [input.metadata.namespace, input.metadata.name])
  expected := object.get(approved_git_source_scopes, key, null)
  expected != null
  object.get(input.spec, "ignore", "") != expected.ignore
  msg := sprintf("GitRepository %s must use the exact fail-closed artifact ignore rules", [key])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  count(object.get(input.spec, "include", [])) > 0
  msg := sprintf("GitRepository %s/%s must not include another source artifact", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  object.get(input.spec, "recurseSubmodules", false) != false
  msg := sprintf("GitRepository %s/%s must not recurse into submodules", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  input.metadata.namespace in tenant_namespaces
  key := sprintf("%s/%s", [input.metadata.namespace, input.metadata.name])
  object.get(input.spec, "url", "") != object.get(approved_git_source_urls, key, "https://github.com/snaraj/website-infrastructure.git")
  msg := sprintf("GitRepository %s/%s must use the canonical anonymous public URL", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  key := sprintf("%s/%s", [input.metadata.namespace, input.metadata.name])
  key in object.keys(approved_git_source_scopes)
  object.get(input.spec, "url", "") != object.get(approved_git_source_urls, key, "")
  msg := sprintf("GitRepository %s must use the canonical anonymous public URL", [key])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  key := sprintf("%s/%s", [input.metadata.namespace, input.metadata.name])
  key in object.keys(approved_git_source_scopes)
  object.get(input.spec, "ref", {}) != {"branch": "main"}
  msg := sprintf("GitRepository %s must track only public main", [key])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  input.metadata.namespace in tenant_namespaces
  object.get(input.spec, "ref", {}) != {"branch": "main"}
  msg := sprintf("GitRepository %s/%s must track only public main", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  is_workload
  restricted_namespace
  some volume in object.get(pod_spec, "volumes", [])
  some source in object.get(object.get(volume, "projected", {}), "sources", [])
  object.get(source, "serviceAccountToken", null) != null
  msg := sprintf("volume %s must not project a ServiceAccount token", [volume.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  expected := object.get(approved_kustomization_accounts, input.metadata.name, "")
  expected == ""
  msg := sprintf("Kustomization %s is not in the reconciliation identity allowlist", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  expected := object.get(approved_kustomization_accounts, input.metadata.name, "")
  expected != ""
  object.get(input.spec, "serviceAccountName", "") != expected
  msg := sprintf("Kustomization %s must use ServiceAccount %s", [input.metadata.name, expected])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  object.get(input.spec, "serviceAccountName", "") != "helm-reconciler"
  msg := sprintf("HelmRelease %s must use ServiceAccount helm-reconciler", [input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  chart_spec := object.get(object.get(input.spec, "chart", {}), "spec", {})
  expected_path := tenant_chart_paths[input.metadata.namespace]
  object.get(chart_spec, "chart", "") != expected_path
  msg := sprintf("HelmRelease %s/%s must use chart %s", [input.metadata.namespace, input.metadata.name, expected_path])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  source_ref := object.get(object.get(object.get(input.spec, "chart", {}), "spec", {}), "sourceRef", {})
  object.get(source_ref, "kind", "") != "GitRepository"
  msg := sprintf("HelmRelease %s/%s must use a GitRepository chart source", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  source_ref := object.get(object.get(object.get(input.spec, "chart", {}), "spec", {}), "sourceRef", {})
  expected_name := tenant_source_names[input.metadata.namespace]
  object.get(source_ref, "name", "") != expected_name
  msg := sprintf("HelmRelease %s/%s must use source %s", [input.metadata.namespace, input.metadata.name, expected_name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  input.metadata.name != input.metadata.namespace
  msg := sprintf("HelmRelease identity %s/%s must be canonical", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  object.get(input.spec, "releaseName", "") != input.metadata.namespace
  msg := sprintf("HelmRelease %s/%s must use canonical releaseName", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind in undiscovered_storage_kinds
  msg := sprintf("%s %s is forbidden until storage discovery and restore evidence are approved", [input.kind, input.metadata.name])
}

deny contains msg if {
  input.kind == "ConfigMap"
  input.metadata.namespace in tenant_namespaces
  count(object.get(input, "binaryData", {})) > 0
  msg := sprintf("ConfigMap %s/%s must not store binary data in etcd", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "Secret"
  input.metadata.namespace in tenant_namespaces
  object.get(input, "type", "Opaque") == "kubernetes.io/service-account-token"
  msg := sprintf("legacy ServiceAccount token Secret %s/%s is forbidden", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind in {"ConfigMap", "Secret"}
  input.metadata.namespace in tenant_namespaces
  entries := sum([count(object.get(input, field, {})) | some field in etcd_payload_fields])
  entries > 4
  msg := sprintf("%s %s/%s exceeds the four-entry control-plane payload boundary", [input.kind, input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind in {"ConfigMap", "Secret"}
  input.metadata.namespace in tenant_namespaces
  some field in etcd_payload_fields
  some key, value in object.get(input, field, {})
  count(value) > 65536
  msg := sprintf("%s %s/%s key %s exceeds the 64 KiB control-plane value boundary", [input.kind, input.metadata.namespace, input.metadata.name, key])
}

deny contains msg if {
  input.kind in {"ConfigMap", "Secret"}
  input.metadata.namespace in tenant_namespaces
  some field in etcd_payload_fields
  some key, _ in object.get(input, field, {})
  regex.match(media_payload_key_pattern, key)
  msg := sprintf("%s %s/%s key %s looks like a media payload", [input.kind, input.metadata.namespace, input.metadata.name, key])
}

deny contains msg if {
  input.kind == "Secret"
  input.metadata.namespace in tenant_namespaces
  some _, value in object.get(input, "data", {})
  regex.match(encoded_media_prefix_pattern, value)
  msg := sprintf("Secret %s/%s contains a recognized encoded media/archive header", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "ConfigMap"
  input.metadata.namespace in tenant_namespaces
  some _, value in object.get(input, "data", {})
  regex.match(encoded_media_prefix_pattern, value)
  msg := sprintf("ConfigMap %s/%s contains a recognized encoded media/archive header", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind in {"ConfigMap", "Secret"}
  input.metadata.namespace in tenant_namespaces
  field := {"ConfigMap": "data", "Secret": "stringData"}[input.kind]
  some _, value in object.get(input, field, {})
  regex.match(`(?is)^\\s*<svg(?:\\s|>)`, value)
  msg := sprintf("%s %s/%s contains inline SVG media", [input.kind, input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "StatefulSet"
  count(object.get(input.spec, "volumeClaimTemplates", [])) > 0
  msg := sprintf("StatefulSet %s must not create claims before storage discovery", [input.metadata.name])
}

deny contains msg if {
  is_workload
  some volume in object.get(pod_spec, "volumes", [])
  some source in undiscovered_pod_volume_sources
  object.get(volume, source, null) != null
  msg := sprintf("volume %s uses undiscovered storage source %s", [volume.name, source])
}

deny contains msg if {
  is_workload
  some toleration in object.get(pod_spec, "tolerations", [])
  object.get(toleration, "key", "") == "node.kubernetes.io/disk-pressure"
  msg := sprintf("%s %s must not tolerate node DiskPressure", [input.kind, input.metadata.name])
}

deny contains msg if {
  is_workload
  some toleration in object.get(pod_spec, "tolerations", [])
  object.get(toleration, "key", "") == ""
  object.get(toleration, "operator", "Equal") == "Exists"
  msg := sprintf("%s %s must not use a wildcard toleration that includes node DiskPressure", [input.kind, input.metadata.name])
}

deny contains msg if {
  is_workload
  restricted_namespace
  namespace := input.metadata.namespace
  some volume in object.get(pod_spec, "volumes", [])
  not valid_tenant_volume(namespace, volume)
  msg := sprintf("volume %s is outside the exact ephemeral/credential volume allowlist for namespace %s", [volume.name, namespace])
}

deny contains msg if {
  input.kind == "ResourceQuota"
  input.metadata.namespace in site_namespaces
  not valid_zero_capacity_quota
  not valid_reviewed_capacity_quota
  msg := sprintf("ResourceQuota %s/%s must be either the exact zero-Pod gate or a hash-bound reviewed namespace budget", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkPolicy"
  input.metadata.namespace in tenant_namespaces
  input.metadata.name == "default-deny"
  not valid_default_deny_policy
  msg := sprintf("NetworkPolicy %s/default-deny must isolate every Pod for ingress and egress", [input.metadata.namespace])
}

deny contains msg if {
  input.kind == "NetworkPolicy"
  input.metadata.namespace in site_namespaces
  count(object.get(input.spec, "ingress", [])) > 0
  not valid_site_ingress_policy
  msg := sprintf("NetworkPolicy %s/%s widens the exact cloudflare-public TCP 8080 ingress contract", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkPolicy"
  input.metadata.namespace in site_namespaces
  count(object.get(input.spec, "egress", [])) > 0
  msg := sprintf("NetworkPolicy %s/%s must not grant site egress", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkPolicy"
  input.metadata.namespace == "cloudflare-public"
  input.metadata.name != "default-deny"
  not valid_public_tunnel_policy
  msg := sprintf("NetworkPolicy cloudflare-public/%s is outside the exact DNS, edge, and site egress allowlist", [input.metadata.name])
}

deny contains msg if {
  is_workload
  object.get(object.get(pod_spec, "securityContext", {}), "runAsNonRoot", false) != true
  msg := sprintf("%s %s must run as non-root", [input.kind, input.metadata.name])
}

deny contains msg if {
  is_workload
  restricted_namespace
  namespace := input.metadata.namespace
  expected_repository := {
    "naranjo-online": "ghcr.io/snaraj/naranjo-online",
    "lidersea-com": "ghcr.io/snaraj/lidersea-com",
    "cloudflare-public": "cloudflare/cloudflared:[A-Za-z0-9._-]+",
  }[namespace]
  some container in containers
  not regex.match(sprintf("^%s@sha256:[0-9a-f]{64}$", [expected_repository]), container.image)
  msg := sprintf("container %s must use the canonical image repository for namespace %s", [container.name, namespace])
}

deny contains msg if {
  is_workload
  object.get(object.get(object.get(pod_spec, "securityContext", {}), "seccompProfile", {}), "type", "") != "RuntimeDefault"
  msg := sprintf("%s %s must use RuntimeDefault seccomp", [input.kind, input.metadata.name])
}

deny contains msg if {
  is_workload
  some container in containers
  object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", true) != false
  msg := sprintf("container %s must disable privilege escalation", [container.name])
}

deny contains msg if {
  is_workload
  restricted_namespace
  some container in object.get(pod_spec, "containers", [])
  resources := object.get(container, "resources", {})
  requests := object.get(resources, "requests", {})
  some resource_name in {"cpu", "memory"}
  object.get(requests, resource_name, "") == ""
  msg := sprintf("container %s must declare a %s request", [container.name, resource_name])
}

deny contains msg if {
  is_workload
  restricted_namespace
  some container in object.get(pod_spec, "containers", [])
  limits := object.get(object.get(container, "resources", {}), "limits", {})
  some resource_name in {"cpu", "memory"}
  object.get(limits, resource_name, "") == ""
  msg := sprintf("container %s must declare a %s limit", [container.name, resource_name])
}

deny contains msg if {
  is_workload
  some container in containers
  object.get(object.get(container, "securityContext", {}), "readOnlyRootFilesystem", false) != true
  msg := sprintf("container %s must use a read-only root filesystem", [container.name])
}

deny contains msg if {
  is_workload
  some container in containers
  object.get(object.get(container, "securityContext", {}), "privileged", false) == true
  msg := sprintf("container %s must not be privileged", [container.name])
}

deny contains msg if {
  is_workload
  some container in containers
  not "ALL" in object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "drop", [])
  msg := sprintf("container %s must drop ALL capabilities", [container.name])
}

deny contains msg if {
  is_workload
  some container in containers
  count(object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "add", [])) > 0
  msg := sprintf("container %s must not add capabilities after dropping ALL", [container.name])
}

deny contains msg if {
  is_workload
  some container in containers
  some port in object.get(container, "ports", [])
  object.get(port, "hostPort", 0) > 0
  msg := sprintf("container %s must not declare a hostPort", [container.name])
}

deny contains msg if {
  is_workload
  some volume in object.get(pod_spec, "volumes", [])
  object.get(volume, "hostPath", null) != null
  msg := sprintf("volume %s must not use hostPath", [volume.name])
}

deny contains msg if {
  is_workload
  some container in containers
  not regex.match("^(ghcr\\.io/(snaraj|fluxcd)/|reg\\.kyverno\\.io/kyverno/|cloudflare/cloudflared:).+@sha256:[0-9a-f]{64}$", container.image)
  msg := sprintf("container %s image must use an approved registry and full digest", [container.name])
}

deny contains msg if {
  input.kind == "Namespace"
  input.metadata.name in tenant_namespaces
  some mode in {"enforce", "audit", "warn"}
  key := sprintf("pod-security.kubernetes.io/%s", [mode])
  object.get(object.get(input.metadata, "labels", {}), key, "") != "restricted"
  msg := sprintf("Namespace %s must set Pod Security %s to restricted", [input.metadata.name, mode])
}

deny contains msg if {
  input.kind == "Namespace"
  input.metadata.name in tenant_namespaces
  some mode in {"enforce", "audit", "warn"}
  key := sprintf("pod-security.kubernetes.io/%s-version", [mode])
  object.get(object.get(input.metadata, "labels", {}), key, "") != "v1.36"
  msg := sprintf("Namespace %s must pin Pod Security %s to v1.36", [input.metadata.name, mode])
}
