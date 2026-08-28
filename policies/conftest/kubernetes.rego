package main

import rego.v1

workload_kinds := {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}

tenant_namespaces := {"cloudflare-public", "naranjo-online", "lidersea-com"}

restricted_role_namespaces := {"cloudflare-public", "naranjo-online", "lidersea-com"}

# Every private, loopback, link-local, carrier-grade-NAT, multicast, and
# reserved block that a "public destinations only" egress rule must exclude.
# One definition, used by every such rule: a shorter list is a wider allow, and
# a set that exists twice is a set that gets widened once.
private_and_reserved_ranges := {
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "224.0.0.0/4",
  "240.0.0.0/4",
}

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

# Static storage objects are admitted only through the owner's enumerated local
# means. These sets are the complete repository-side enumeration; hostile
# fixtures and tests pin every kind and degenerate shape independently of any
# runtime admission engine.
storage_kinds := {
  "PersistentVolume",
  "PersistentVolumeClaim",
  "StorageClass",
  "CSIDriver",
  "VolumeAttributesClass",
}

enumerated_storage_classes := {"local-pie-ssd"}

enumerated_storage_provisioners := {"kubernetes.io/no-provisioner"}

# Empty by design: no CSI driver is an enumerated means today.
enumerated_csi_drivers := set()

enumerated_local_volume_roots := {"/mnt/local-pie-ssd"}

# Empty by design, and for the same reason the driver list is: no
# VolumeAttributesClass may exist, so no PersistentVolume or claim may reference
# one. SR-14 gates the OBJECT; SR-15 gates the REFERENCE, exactly as SR-9 gates
# the StorageClass object and SR-7/SR-11 gate references to it.
enumerated_volume_attributes_classes := set()

admitted_persistent_volume_sources := {"local", "csi"}

# Every PersistentVolumeSpec field that is not a volume source. Sources are
# derived by subtraction, so an unrecognized source is a source.
persistent_volume_non_source_fields := {
  "accessModes",
  "capacity",
  "claimRef",
  "mountOptions",
  "nodeAffinity",
  "persistentVolumeReclaimPolicy",
  "storageClassName",
  "volumeAttributesClassName",
  "volumeMode",
}

# Pod-level storage is a separate gate from the storage OBJECTS above: admitting
# a PersistentVolume did not admit mounting one. It used to be a ten-name
# BLOCKLIST of the network sources upstream had invented by then, which meant an
# otherwise compliant Pod could mount `azureFile` or `awsElasticBlockStore` and
# be admitted (measured on wi #96, 2026-08-12, in a non-tenant namespace). It now
# uses the SAME SUBTRACTION MODEL as the PersistentVolume rules: a Pod volume
# entry is a name plus exactly one source, the source is whatever is left when
# the non-source fields are removed, and only sources whose bytes come from the
# cluster's own API server or the node's ephemeral storage are admitted. Every
# network filesystem, every cloud disk, every claim/CSI reference, and every
# source upstream has not invented yet is denied by construction.
pod_volume_non_source_fields := {"name"}

admitted_pod_volume_sources := {
  "emptyDir",
  "configMap",
  "secret",
  "projected",
  "downwardAPI",
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

# The Pod-level metadata that carries the workload identity labels. Static
# policy needs it because a connector's mounted Secret must be bound to that
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
  "naranjo-online-reconciler": "naranjo-online-reconciler",
  "lidersea-com-reconciler": "lidersea-com-reconciler",
}

approved_kustomization_paths := {
  "naranjo-online-reconciler": "./kubernetes/websites/naranjo-online",
  "lidersea-com-reconciler": "./kubernetes/websites/lidersea-com",
}

approved_kustomization_dependencies := {
  "naranjo-online-reconciler": set(),
  "lidersea-com-reconciler": set(),
}

site_workload_accounts := {
  "naranjo-online": "naranjo-online",
  "lidersea-com": "lidersea-com",
}

# Only the connector release still resolves its chart from a Git source; both
# site namespaces moved to published, signature-verified OCI chart artifacts,
# so a GitRepository in a site namespace has no legitimate identity at all.
tenant_source_names := {
  "cloudflare-public": "cloudflare-public-source",
}

tenant_chart_paths := {
  "cloudflare-public": "./kubernetes/platform/cloudflare-public/chart",
}

git_chart_namespaces := {"cloudflare-public"}

# Each site's Helm chart is published by that site's own release publisher at a
# stable version tag, so the published version tag is the release identity Flux
# follows. The publisher itself is dispatched from protected `main`, which is a
# separate thing from the version it publishes under — see
# `site_chart_identities` below.
site_chart_sources := {
  "naranjo-online": "naranjo-online-chart",
  "lidersea-com": "lidersea-com-chart",
}

site_chart_urls := {
  "naranjo-online": "oci://ghcr.io/snaraj/charts/naranjo-online",
  "lidersea-com": "oci://ghcr.io/snaraj/charts/lidersea-com",
}

# The audit tag is paired with the immutable manifest digest Flux consumes.
# The annotation is not a selector; exact ref.digest is load-bearing.
site_chart_releases := {
  "naranjo-online": {
    "tag": "0.1.54",
    "digest": "sha256:7223dd78f308c1e211da71f6e062195724aaedc47962b0a04907eeb0baf2d7bb",
  },
  "lidersea-com": {
    "tag": "0.1.37",
    "digest": "sha256:05ab03a6e7520ea6768e4efc3750c83f8f7bc827cac3289bf9ee1326c873c8fc",
  },
}

site_chart_layer_media_type := "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

# The exact keyless certificate identity of each site's chart publisher. These
# two tuples must never couple: a chart signed by the other site's workflow, by
# another workflow in the same repository, or by a run at any ref other than
# that repository's protected `main` — a tag ref included — is denied. The
# branch ref is the anchor because a run at a ref executes the workflow
# definition AT that ref, and `main` is the only ref those repositories gate on
# creation and update with no bypass actors (ADR 0016 amendment 2026-08-22).
site_chart_identities := {
  "naranjo-online": {
    "issuer": `^https://token\.actions\.githubusercontent\.com$`,
    "subject": `^https://github\.com/snaraj/naranjo\.online/\.github/workflows/release-publisher\.yml@refs/heads/main$`,
  },
  "lidersea-com": {
    "issuer": `^https://token\.actions\.githubusercontent\.com$`,
    "subject": `^https://github\.com/snaraj/lidersea\.com/\.github/workflows/release-publisher\.yml@refs/heads/main$`,
  },
}

approved_git_source_scopes := {
  "cloudflare-public/cloudflare-public-source": {
    "ignore": "/*\n!/kubernetes\n/kubernetes/*\n!/kubernetes/platform\n/kubernetes/platform/*\n!/kubernetes/platform/cloudflare-public\n/kubernetes/platform/cloudflare-public/*\n!/kubernetes/platform/cloudflare-public/chart\n",
    "sparseCheckout": ["kubernetes/platform/cloudflare-public/chart"],
  },
}

approved_git_source_refs := {
  "cloudflare-public/cloudflare-public-source": {"branch": "main"},
}

# The remaining tenant source pulls this repository; nothing else may.
approved_git_source_urls := {
  "cloudflare-public/cloudflare-public-source": "https://github.com/snaraj/website-infrastructure.git",
}

valid_site_chart_verification(namespace) if {
  verify := object.get(input.spec, "verify", {})
  object.get(verify, "provider", "") == "cosign"
  object.get(verify, "secretRef", null) == null
  identities := object.get(verify, "matchOIDCIdentity", [])
  count(identities) == 1
  identities[0] == site_chart_identities[namespace]
}

# The one name a site's ingress policy may carry. Reconciled to the cluster on
# 2026-08-12: the live objects are `ingress-to-<namespace>` and both site
# charts render that name, while this contract alone still demanded the
# superseded `cloudflared-to-` prefix — so every render of the real desired
# state was refused by a check that was modelling a shape nothing deploys.
#
# Kept as an exact literal rather than a configurable value on purpose. A
# values-derived prefix would silently diverge from the reviewed desired-state
# contract. Accepting BOTH
# prefixes was rejected outright: it would weaken an exact-name match into an
# alternation, and an alternation is what lets a superseded identity survive.
# The literal is also the provider-NEUTRAL one (delivery-lane requirement 7):
# `cloudflared-` named the provider, which the site repositories removed on
# 2026-08-10 and their own neutrality test now forbids re-adding.
site_ingress_policy_name(namespace) := sprintf("ingress-to-%s", [namespace])

valid_site_ingress_policy if {
  namespace := input.metadata.namespace
  namespace in site_namespaces
  input.metadata.name == site_ingress_policy_name(namespace)

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
  {cidr | some cidr in object.get(ip_block, "except", [])} == private_and_reserved_ranges
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

# The Flux controller install ships three NetworkPolicies of its own. Two are
# ingress-only as generated; `allow-egress` is generated with a blanket
# `egress: [{}]` that this repository removes by patch, so accepting any of the
# three with an egress rule would accept exactly the regression the patch
# exists to prevent.
flux_generated_network_policies := {"allow-egress", "allow-scraping", "allow-webhooks"}

# Every deliberate flux-system egress allow selects the controller Pods by the
# label the generated export puts on all three, grants Egress only, and carries
# exactly one rule. One rule per policy is what keeps each allow separately
# reviewable and separately revocable.
flux_controller_egress_shape if {
  object.get(object.get(input.spec, "podSelector", {}), "matchLabels", {}) == {
    "app.kubernetes.io/part-of": "flux",
  }
  {policy_type | some policy_type in object.get(input.spec, "policyTypes", [])} == {"Egress"}
  count(object.get(input.spec, "ingress", [])) == 0
  count(object.get(input.spec, "egress", [])) == 1
}

valid_flux_artifact_rule(rule) if {
  object.get(rule, "to", []) == [{
    "podSelector": {"matchLabels": {"app.kubernetes.io/part-of": "flux"}},
  }]
  {port | some port in object.get(rule, "ports", [])} == {
    {"port": 80, "protocol": "TCP"},
    {"port": 9090, "protocol": "TCP"},
  }
}

valid_flux_public_https_rule(rule) if {
  peers := object.get(rule, "to", [])
  count(peers) == 1
  peer := peers[0]
  object.keys(peer) == {"ipBlock"}
  ip_block := object.get(peer, "ipBlock", {})
  object.get(ip_block, "cidr", "") == "0.0.0.0/0"
  {cidr | some cidr in object.get(ip_block, "except", [])} == private_and_reserved_ranges
  object.get(rule, "ports", []) == [{"port": 443, "protocol": "TCP"}]
}

# The API-server destination is host inventory and never enters this index, so
# the committed rule is pinned to the RFC 5737 documentation address that can
# never match a real endpoint. Pinning it here also means a real control-plane
# address committed by mistake is a policy failure, not just a privacy failure.
valid_flux_apiserver_rule(rule) if {
  peers := object.get(rule, "to", [])
  count(peers) == 1
  peer := peers[0]
  object.keys(peer) == {"ipBlock"}
  object.get(peer, "ipBlock", {}) == {"cidr": "192.0.2.0/32"}
  object.get(rule, "ports", []) == [{"port": 6443, "protocol": "TCP"}]
}

valid_flux_egress_policy if {
  flux_controller_egress_shape
  input.metadata.name == "flux-controllers-dns"
  valid_public_dns_rule(input.spec.egress[0])
}

valid_flux_egress_policy if {
  flux_controller_egress_shape
  input.metadata.name == "flux-controllers-artifacts"
  valid_flux_artifact_rule(input.spec.egress[0])
}

valid_flux_egress_policy if {
  flux_controller_egress_shape
  input.metadata.name == "flux-controllers-public-https"
  valid_flux_public_https_rule(input.spec.egress[0])
}

valid_flux_egress_policy if {
  flux_controller_egress_shape
  input.metadata.name == "flux-controllers-kube-apiserver"
  object.get(object.get(input.metadata, "annotations", {}), "platform.snaraj.dev/readiness", "") == "sentinel-until-private-calico-api-endpoint-set"
  valid_flux_apiserver_rule(input.spec.egress[0])
}

flux_network_policy_allowlisted if {
  input.metadata.name in flux_generated_network_policies
}

flux_network_policy_allowlisted if {
  input.metadata.name == "default-deny"
}

flux_network_policy_allowlisted if {
  valid_flux_egress_policy
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
  object.get(annotations, "platform.snaraj.dev/capacity-evidence-sha256", "") == "955a59cbf5ba0bd36f5e62349ed070a2b1eba6fb3ef072951435010edcceaf34"
  object.get(input.spec, "hard", {}) == {
    "pods": "6",
    "requests.cpu": "150m",
    "requests.memory": "192Mi",
    "limits.cpu": "1200m",
    "limits.memory": "768Mi",
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

# The reviewed connector Deployment inventory (ADR 0015): one per website.
connector_deployments := {"naranjo-online-tunnel", "lidersea-com-tunnel"}

public_connector_deployment if {
  input.kind == "Deployment"
  object.get(input.metadata, "namespace", "") == "cloudflare-public"
}

public_connector_workload if {
  is_workload
  object.get(object.get(input, "metadata", {}), "namespace", "") == "cloudflare-public"
}

# The OTHER token-delivery surface, and the one the cluster actually runs.
# Captured live 2026-08-12: both connector Pods mount ZERO volumes and receive
# the Tunnel credential as `env: TUNNEL_TOKEN` with
# `valueFrom.secretKeyRef`. The volume rule above therefore governs a shape
# that is not deployed — and because it is written as "every volume must be
# the own-instance tunnel-token volume", a Pod with no volumes at all
# satisfies it vacuously. So the cross-site substitution closed on the volume
# surface was still wide open on the surface in production: a connector Pod
# naming the OTHER site's Secret in a secretKeyRef passed every gate.
#
# This binds that surface by the SAME derivation as the volume rule — the
# Secret name must equal the connector's own app.kubernetes.io/instance plus
# `-token` — and the instance a DEPLOYMENT may claim is itself rooted in that
# Deployment's name by connector_identity_rooted_in_name.
#
# DECLARED LIMIT, stated because the honest scope is narrower than "no
# self-consistent relabelling anywhere". That rooting is scoped to
# `input.kind == "Deployment"`, since a bare Pod has no name to root in — its
# name is generated — and no selector or template to compare against. So a
# BARE Pod that moves its instance label and its secretKeyRef together stays
# internally consistent and is admitted. Three things bound what that buys an
# attacker, and none of them is this rule: the label that selects the token is
# the SAME label both site NetworkPolicies select on, so such a Pod is a
# duplicate of the site it claims rather than a bridge to the other one; the
# closed connector inventory below still refuses an identity outside the
# reviewed two; and creating a bare Pod in this namespace is not a right any
# reviewed principal holds. Closing it properly means requiring a controller
# ownerReference on Pods here, which would rewrite every connector fixture in
# the repository and is a separate static-policy change in its own right —
# tracked, not smuggled into this change.
#
# `envFrom` is refused outright rather than pattern-matched: a `secretRef`
# there injects EVERY key of the named Secret with no key selector to bind, so
# an allowlist would have to reason about the Secret's contents, which manifest
# policy cannot inspect. The deployed connectors declare no envFrom at all, so
# refusing it costs nothing and closes the second door into the same credential.
connector_secret_env_binding_is_own_instance if {
  connector_instance in connector_deployments
  every container in containers {
    valid_connector_container_env(container)
  }
}

# Written as a POSITIVE proof that the denial NEGATES, never as a rule that
# hunts for a violation. A missing, null, scalar or map-shaped `env`, a
# non-object container, or a non-list `containers` makes this proof UNDEFINED
# and `not` then fires the denial. A mismatch-hunting rule would instead go
# undefined itself on exactly those degenerate shapes — under OPA's default
# non-strict mode a builtin type error silently drops the deny body and fails
# open on exactly those degenerate shapes.
valid_connector_container_env(container) if {
  is_object(container)
  not "envFrom" in object.keys(container)
  env := object.get(container, "env", [])
  is_array(env)
  every entry in env {
    valid_connector_env_entry(entry)
  }
}

# An env entry that reads no Secret at all is none of this rule's business.
valid_connector_env_entry(entry) if {
  is_object(entry)
  value_from := object.get(entry, "valueFrom", {})
  is_object(value_from)
  not "secretKeyRef" in object.keys(value_from)
}

# An env entry that DOES read a Secret must read exactly this connector's own
# token key. Compared by whole-object equality so an added `optional: true`
# — which would let the Pod start with no credential at all, silently — is a
# denial rather than an accepted extra field.
valid_connector_env_entry(entry) if {
  is_object(entry)
  value_from := object.get(entry, "valueFrom", {})
  is_object(value_from)
  object.get(value_from, "secretKeyRef", {}) == {
    "name": sprintf("%s-token", [connector_instance]),
    "key": "token",
  }
}

# The connector identity tuple is ROOTED IN THE DEPLOYMENT NAME, never in a
# caller-supplied label. Deriving the expected token from the instance label
# alone leaves an internally self-consistent bypass: keep the allowlisted
# `lidersea-com-tunnel` Deployment name, move its metadata/selector/template
# instance labels AND its mounted Secret to the other site, and every
# instance-derived check agrees with itself while that Deployment's Pods
# consume the other website's runtime credential.
#
# Written as a POSITIVE proof that its denial NEGATES, never as a rule that
# hunts for a mismatch. A missing, null, scalar, or list `labels` makes the
# proof below UNDEFINED, and `not` then fires the denial. A mismatch-hunting
# rule would instead go undefined itself on exactly those degenerate shapes —
# under OPA's default non-strict mode a builtin type error silently drops the
# deny body and fails open on exactly those degenerate shapes.
connector_identity_rooted_in_name if {
  input.metadata.labels["app.kubernetes.io/instance"] == input.metadata.name
  input.spec.selector.matchLabels["app.kubernetes.io/instance"] == input.metadata.name
  input.spec.template.metadata.labels["app.kubernetes.io/instance"] == input.metadata.name
}

valid_source_controller_storage if {
  containers := object.get(input.spec.template.spec, "containers", [])
  count(containers) == 1
  manager := containers[0]
  manager.name == "manager"
  resources := object.get(manager, "resources", {})
  object.get(object.get(resources, "requests", {}), "ephemeral-storage", "") == "128Mi"
  object.get(object.get(resources, "limits", {}), "ephemeral-storage", "") == "1Gi"
  # source-controller does not accept the reconciler-only flags. Requiring one
  # here used to be the rule; the binary exits 2 on an unknown flag, so the
  # requirement guaranteed a crashloop. Refusing them is the correct direction:
  # the cross-namespace boundary is enforced on the controllers that own the
  # referring kinds, and this keeps a well-meant copy-paste from landing here.
  count([flag |
    some flag in object.get(manager, "args", [])
    startswith(flag, "--no-cross-namespace-refs")
  ]) == 0
  count([flag |
    some flag in object.get(manager, "args", [])
    startswith(flag, "--default-service-account")
  ]) == 0
  count([flag |
    some flag in object.get(manager, "args", [])
    startswith(flag, "--no-remote-bases")
  ]) == 0
  count([flag |
    some flag in object.get(manager, "args", [])
    startswith(flag, "--feature-gates=")
  ]) == 0

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

valid_helm_readback_rule(rule) if {
  input.metadata.name == "helm-reconciler"
  input.metadata.namespace in tenant_namespaces
  rule == {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}
}

valid_naranjo_pvc_rule(rule) if {
  input.metadata.name == "helm-reconciler"
  input.metadata.namespace == "naranjo-online"
  rule == {"apiGroups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]}
}

deny contains msg if {
  input.kind == "Role"
  some rule in object.get(input, "rules", [])
  "persistentvolumeclaims" in object.get(rule, "resources", [])
  not valid_naranjo_pvc_rule(rule)
  msg := sprintf("Role %s/%s must grant PVC lifecycle only as the exact naranjo-online helm-reconciler rule", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "ClusterRole"
  some rule in object.get(input, "rules", [])
  "persistentvolumeclaims" in object.get(rule, "resources", [])
  msg := sprintf("ClusterRole %s must not grant cluster-wide PVC authority", [input.metadata.name])
}

valid_helm_readback_rule(rule) if {
  input.metadata.name == "helm-reconciler"
  input.metadata.namespace in tenant_namespaces
  rule == {"apiGroups": ["apps"], "resources": ["replicasets"], "verbs": ["get", "list", "watch"]}
}

deny contains msg if {
  input.kind == "Role"
  input.metadata.namespace in restricted_role_namespaces
  some rule in object.get(input, "rules", [])
  some resource in object.get(rule, "resources", [])
  resource in {"pods", "pods/exec", "replicasets", "daemonsets", "statefulsets", "jobs", "cronjobs"}
  not valid_helm_readback_rule(rule)
  msg := sprintf("Role %s/%s must not grant direct %s workload control outside the exact Helm readiness read-back", [input.metadata.namespace, input.metadata.name, resource])
}

deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace == "flux-system"
  input.metadata.name == "source-controller"
  not valid_source_controller_storage
  msg := "source-controller must bound /data and /tmp plus container ephemeral-storage, and must carry no reconciler-only flag it cannot parse"
}

valid_reconciler_config_watcher_gate if {
  managers := [container |
    some container in object.get(input.spec.template.spec, "containers", [])
    object.get(container, "name", "") == "manager"
  ]
  count(managers) == 1
  feature_gates := [argument |
    some argument in object.get(managers[0], "args", [])
    startswith(argument, "--feature-gates=")
  ]
  feature_gates == ["--feature-gates=DisableConfigWatchers=true"]
}

deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace == "flux-system"
  input.metadata.name in {"kustomize-controller", "helm-controller"}
  not valid_reconciler_config_watcher_gate
  msg := sprintf("%s must disable ConfigMap and Secret event watchers with the exact reviewed feature gate", [input.metadata.name])
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
  input.metadata.name in object.keys(approved_kustomization_accounts)
  object.get(input.spec, "wait", false) != true
  msg := sprintf("Kustomization %s must wait for runtime readiness", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  input.metadata.name in object.keys(approved_kustomization_accounts)
  object.get(input.spec, "prune", true) != false
  msg := sprintf("Kustomization %s must not prune during the direct release boundary", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  input.metadata.name in object.keys(approved_kustomization_accounts)
  object.get(input.spec, "deletionPolicy", "") != "Orphan"
  msg := sprintf("Kustomization %s must orphan inventory on deletion", [input.metadata.name])
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

# Site charts are published, signed OCI artifacts. Any Git chart source in a
# site namespace would reintroduce branch-head tracking with no signature
# verification at all, so the kind itself is denied there.
deny contains msg if {
  input.kind == "GitRepository"
  input.metadata.namespace in site_namespaces
  msg := sprintf("GitRepository %s/%s is forbidden; site charts arrive as cosign-verified OCI artifacts", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in site_namespaces
  expected_name := site_chart_sources[input.metadata.namespace]
  input.metadata.name != expected_name
  msg := sprintf("OCIRepository %s/%s must use canonical identity %s", [input.metadata.namespace, input.metadata.name, expected_name])
}

deny contains msg if {
  input.kind == "OCIRepository"
  not input.metadata.namespace in site_namespaces
  msg := sprintf("OCIRepository %s/%s is outside the exact chart-source identity allowlist", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in site_namespaces
  object.get(input.spec, "url", "") != site_chart_urls[input.metadata.namespace]
  msg := sprintf("OCIRepository %s/%s must pull the canonical published chart repository", [input.metadata.namespace, input.metadata.name])
}

# Exactly one selector shape: an immutable nonzero digest. Registry tag moves,
# deletion, or replacement cannot change what Flux pulls.
deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in site_namespaces
  object.get(input.spec, "ref", {}) != {"digest": site_chart_releases[input.metadata.namespace].digest}
  msg := sprintf("OCIRepository %s/%s must select the exact reviewed immutable chart digest", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in site_namespaces
  object.get(object.get(input.metadata, "annotations", {}), "platform.snaraj.dev/chart-release", "") != site_chart_releases[input.metadata.namespace].tag
  msg := sprintf("OCIRepository %s/%s must carry the reviewed audit-only chart release annotation", [input.metadata.namespace, input.metadata.name])
}

# The reconcile-time half of the digest-only invariant: an unsigned chart, or a
# chart signed by any identity other than this exact site's publisher, never
# becomes an artifact.
deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in site_namespaces
  not valid_site_chart_verification(input.metadata.namespace)
  msg := sprintf("OCIRepository %s/%s must verify chart signatures against this site's exact keyless publisher identity", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in site_namespaces
  object.get(object.get(input.spec, "layerSelector", {}), "mediaType", "") != site_chart_layer_media_type
  msg := sprintf("OCIRepository %s/%s must extract only the Helm chart layer media type", [input.metadata.namespace, input.metadata.name])
}

# The cluster holds no registry credential, exactly as it holds no Git
# credential. Anonymous public pulls only; no ServiceAccount pull secrets, no
# client certificates, no proxy credential, and no plaintext registry.
deny contains msg if {
  input.kind == "OCIRepository"
  some field in {"serviceAccountName", "certSecretRef", "proxySecretRef"}
  object.get(input.spec, field, null) != null
  msg := sprintf("OCIRepository %s/%s must use anonymous public registry access (%s is forbidden)", [input.metadata.namespace, input.metadata.name, field])
}

deny contains msg if {
  input.kind == "OCIRepository"
  object.get(input.spec, "insecure", false) != false
  msg := sprintf("OCIRepository %s/%s must not pull over plaintext HTTP", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "OCIRepository"
  object.get(input.spec, "provider", "generic") != "generic"
  msg := sprintf("OCIRepository %s/%s must not use a cloud-provider credential chain", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "OCIRepository"
  object.get(input.spec, "suspend", false) != false
  msg := sprintf("OCIRepository %s/%s must not be independently suspended; suspension is a HelmRelease and Kustomization decision", [input.metadata.namespace, input.metadata.name])
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
  object.get(input.spec, "ref", {}) != approved_git_source_refs[key]
  msg := sprintf("GitRepository %s must use its exact reviewed ref", [key])
}

deny contains msg if {
  input.kind == "GitRepository"
  input.apiVersion == "source.toolkit.fluxcd.io/v1"
  input.metadata.namespace in tenant_namespaces
  input.metadata.namespace != "flux-system"
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

# DisableConfigWatchers removes the controller's broad ConfigMap/Secret event
# informers. Keep the current production contract closed over inline values and
# the local API server; a future external input needs an explicit namespaced
# grant and a separately reviewed design.
deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  object.get(input.spec, "valuesFrom", []) != []
  msg := sprintf("HelmRelease %s/%s must not use valuesFrom under the closed controller RBAC contract", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  object.get(input.spec, "kubeConfig", null) != null
  msg := sprintf("HelmRelease %s/%s must not use kubeConfig under the closed controller RBAC contract", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  object.get(input.spec, "storageNamespace", null) != null
  msg := sprintf("HelmRelease %s/%s must not redirect Helm storage to another namespace", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in tenant_namespaces
  object.get(input.spec, "targetNamespace", null) != null
  msg := sprintf("HelmRelease %s/%s must not redirect rendered workloads to another namespace", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in git_chart_namespaces
  chart_spec := object.get(object.get(input.spec, "chart", {}), "spec", {})
  expected_path := tenant_chart_paths[input.metadata.namespace]
  object.get(chart_spec, "chart", "") != expected_path
  msg := sprintf("HelmRelease %s/%s must use chart %s", [input.metadata.namespace, input.metadata.name, expected_path])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in git_chart_namespaces
  source_ref := object.get(object.get(object.get(input.spec, "chart", {}), "spec", {}), "sourceRef", {})
  object.get(source_ref, "kind", "") != "GitRepository"
  msg := sprintf("HelmRelease %s/%s must use a GitRepository chart source", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in git_chart_namespaces
  source_ref := object.get(object.get(object.get(input.spec, "chart", {}), "spec", {}), "sourceRef", {})
  expected_name := tenant_source_names[input.metadata.namespace]
  object.get(source_ref, "name", "") != expected_name
  msg := sprintf("HelmRelease %s/%s must use source %s", [input.metadata.namespace, input.metadata.name, expected_name])
}

# A site release is bound to its published chart artifact and to nothing else.
# An inline chart block would reintroduce branch-head tracking beside the
# digest-selected source and give the release two competing chart identities.
valid_site_release_values if {
  spec := object.get(input, "spec", null)
  is_object(spec)
  object.get(spec, "values", null) == {"deploymentReady": true}
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in site_namespaces
  not valid_site_release_values
  msg := sprintf("HelmRelease %s values must contain exactly deploymentReady: true", [input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in site_namespaces
  object.get(input.spec, "chart", null) != null
  msg := sprintf("HelmRelease %s/%s must not carry an inline chart; site charts arrive as published OCI artifacts", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in site_namespaces
  object.get(object.get(input.spec, "chartRef", {}), "kind", "") != "OCIRepository"
  msg := sprintf("HelmRelease %s/%s must resolve its chart through an OCIRepository chartRef", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in site_namespaces
  expected_name := site_chart_sources[input.metadata.namespace]
  object.get(object.get(input.spec, "chartRef", {}), "name", "") != expected_name
  msg := sprintf("HelmRelease %s/%s must use chart source %s", [input.metadata.namespace, input.metadata.name, expected_name])
}

# An explicit chartRef namespace is the one way a site could be pointed at the
# other site's published chart even with helm-controller's cross-namespace
# refs disabled at some future date; deny it in desired state too.
deny contains msg if {
  input.kind == "HelmRelease"
  input.apiVersion == "helm.toolkit.fluxcd.io/v2"
  input.metadata.namespace in site_namespaces
  object.get(object.get(input.spec, "chartRef", {}), "namespace", input.metadata.namespace) != input.metadata.namespace
  msg := sprintf("HelmRelease %s/%s must not reference a cross-namespace chart source", [input.metadata.namespace, input.metadata.name])
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

# A storage object may be structurally unusable — no metadata, a truncated
# document, a spec that is not a mapping. Reading a name out of it must never be
# the thing that makes a deny rule undefined, because an undefined deny rule is
# an allow.
storage_object_name := name if {
  name := object.get(object.get(input, "metadata", {}), "name", "")
  is_string(name)
  name != ""
} else := "<unnamed>"

storage_object_spec := spec if {
  spec := object.get(input, "spec", {})
  is_object(spec)
} else := {}

# EVERY sub-structure below is read through this helper instead of a nested
# object.get, because a NESTED object.get FAILS OPEN. When the inner value is
# null, a string, or a list, the outer object.get raises a builtin TYPE ERROR;
# under OPA's default non-strict builtin-error handling the whole expression is
# UNDEFINED, the deny body fails, and the rule SILENTLY DOES NOT FIRE. A prior
# differential review found nine such shapes, eight fail-open in Rego.
# Yielding {} for a degenerate value makes every read below fall back to the
# empty value its rule already denies on, so "present but unusable" denies for
# the same reason "absent" does. The storage fixture battery pins all of those
# degenerate cases and their exact denial attribution.
storage_sub_object(parent, key) := value if {
  value := object.get(parent, key, {})
  is_object(value)
} else := {}

# Presence, distinguished from an explicit null. object.get cannot tell "absent"
# from "present but null"; a historical comparison with the retired CEL mirror
# exposed that a Rego arm keyed on non-nullness admitted the explicitly-null
# field. The retained static rule therefore keys on declaration.
storage_spec_declares(field) if {
  field in object.keys(storage_object_spec)
}

empty_collection(value) if {
  is_object(value)
  count(value) == 0
}

empty_collection(value) if {
  is_array(value)
  count(value) == 0
}

# storage_kinds is the mirror's declared surface, so every storage deny arm is
# gated on membership: dropping a kind from that set stops the mirror covering
# it, which is a behavioural change the deny fixtures catch, not just a
# structural one.
is_storage_object if {
  input.kind in storage_kinds
}

persistent_volume_sources := {field |
  some field, _ in storage_object_spec
  not field in persistent_volume_non_source_fields
}

# SR-0. A spec that is absent, or present but not a mapping, cannot be reasoned
# about, so it is denied rather than skipped. Presence is checked explicitly.
# A historical comparison with the retired CEL mirror exposed that
# object.get(input, "spec", {}) returned {} for an absent spec and left this
# static arm silently weaker.
deny contains msg if {
  is_storage_object
  input.kind in {"PersistentVolume", "PersistentVolumeClaim"}
  not storage_object_has_usable_spec
  msg := sprintf("%s %s has no usable spec mapping and cannot be evaluated", [input.kind, storage_object_name])
}

storage_object_has_usable_spec if {
  "spec" in object.keys(input)
  is_object(input.spec)
}

# SR-1. Exactly one volume source; zero (absent/empty/truncated spec) and two
# (a local decoy beside a remote source) both deny.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolume"
  count(persistent_volume_sources) != 1
  msg := sprintf("PersistentVolume %s must declare exactly one volume source, found %d", [storage_object_name, count(persistent_volume_sources)])
}

# SR-2. Derived by subtraction, so nfs, iscsi, cephfs, glusterfs, fc, rbd,
# portworxVolume, flexVolume, azureFile, azureDisk, awsElasticBlockStore,
# gcePersistentDisk, vsphereVolume, cinder, hostPath and every future source are
# denied without maintaining a blocklist.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolume"
  some source in persistent_volume_sources
  not source in admitted_persistent_volume_sources
  msg := sprintf("PersistentVolume %s uses volume source %s, which is not an enumerated local means", [storage_object_name, source])
}

# SR-3. A csi source reaches wherever its driver reaches. A csi value that is
# null, a scalar, or a list yields {} here and therefore an empty driver name,
# which is not enumerated and denies. A historical comparison with the retired
# CEL mirror exposed this malformed shape by erroring.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolume"
  "csi" in persistent_volume_sources
  not object.get(storage_sub_object(storage_object_spec, "csi"), "driver", "") in enumerated_csi_drivers
  msg := sprintf("PersistentVolume %s names a CSI driver outside the enumerated local-provisioner allowlist", [storage_object_name])
}

# SR-4. A local path outside the enumerated root is a different means. A local
# value that is null, a scalar, or a list yields {} and therefore an empty path,
# which is under no enumerated root and denies.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolume"
  "local" in persistent_volume_sources
  path := object.get(storage_sub_object(storage_object_spec, "local"), "path", "")
  not local_path_under_enumerated_root(path)
  msg := sprintf("PersistentVolume %s uses local path outside the enumerated local root", [storage_object_name])
}

# SR-5. Prefix matching alone accepts "<root>/../../var/lib/etcd". The is_string
# guard keeps a non-string path from making contains() error, which would make
# this arm undefined instead of leaving SR-4 to deny the object.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolume"
  "local" in persistent_volume_sources
  path := object.get(storage_sub_object(storage_object_spec, "local"), "path", "")
  is_string(path)
  contains(path, "..")
  msg := sprintf("PersistentVolume %s uses a local path containing a parent traversal segment", [storage_object_name])
}

# SR-6. Required node affinity that does not BOUND the node set is not a pin:
# `operator: Exists` on kubernetes.io/hostname is satisfied by every node that
# ever joins, and `required: {}` asserts nothing at all. Both were admitted while
# this rule only checked that `required` was present, which is less than its
# stated purpose (wi #96 review). It now requires at least one node selector
# term, and requires EVERY term to name the nodes it accepts through an `In`
# match with a non-empty value list.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolume"
  "local" in persistent_volume_sources
  not local_volume_is_bound_to_named_nodes
  msg := sprintf("PersistentVolume %s must pin itself to named nodes with a bounded required nodeAffinity", [storage_object_name])
}

local_volume_is_bound_to_named_nodes if {
  required := storage_sub_object(storage_sub_object(storage_object_spec, "nodeAffinity"), "required")
  terms := object.get(required, "nodeSelectorTerms", [])
  is_array(terms)
  count(terms) > 0
  every term in terms {
    node_selector_term_names_nodes(term)
  }
}

node_selector_term_names_nodes(term) if {
  some matcher in ["matchExpressions", "matchFields"]
  some expression in object.get(term, matcher, [])
  object.get(expression, "operator", "") == "In"
  values := object.get(expression, "values", [])
  is_array(values)
  count(values) > 0
}

# SR-7. The class name is part of the enumerated means.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolume"
  not object.get(storage_object_spec, "storageClassName", "") in enumerated_storage_classes
  msg := sprintf("PersistentVolume %s must declare an enumerated storageClassName", [storage_object_name])
}

# SR-8. The provisioner IS the means.
deny contains msg if {
  is_storage_object
  input.kind == "StorageClass"
  not object.get(input, "provisioner", "") in enumerated_storage_provisioners
  msg := sprintf("StorageClass %s must use an enumerated local provisioner", [storage_object_name])
}

# SR-9. A second class must not appear beside the reviewed one.
deny contains msg if {
  is_storage_object
  input.kind == "StorageClass"
  not storage_object_name in enumerated_storage_classes
  msg := sprintf("StorageClass %s is not an enumerated class identity", [storage_object_name])
}

# SR-10. parameters/mountOptions is where a server, export, share, endpoint, or
# bucket would be named; a static local class needs neither. Declared-but-
# degenerate values (null, a scalar, the wrong collection type) deny too: count()
# raises a type error on a non-collection, and an erroring expression is
# UNDEFINED, which would have skipped the rule rather than denying.
deny contains msg if {
  is_storage_object
  input.kind == "StorageClass"
  some field in {"parameters", "mountOptions"}
  field in object.keys(input)
  not empty_collection(input[field])
  msg := sprintf("StorageClass %s must declare no parameters and no mountOptions", [storage_object_name])
}

# SR-11. An absent class silently binds through the cluster default class.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolumeClaim"
  not object.get(storage_object_spec, "storageClassName", "") in enumerated_storage_classes
  msg := sprintf("PersistentVolumeClaim %s must name an enumerated storageClassName", [storage_object_name])
}

# SR-12. dataSource/dataSourceRef import bytes the enumeration never described.
# Keyed on DECLARATION, not on non-nullness: `dataSourceRef:` with a null value
# is a declared import. A historical comparison with the retired CEL mirror
# exposed that it was admitted here while this arm compared the value against
# null.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolumeClaim"
  some field in {"dataSource", "dataSourceRef"}
  storage_spec_declares(field)
  msg := sprintf("PersistentVolumeClaim %s must not populate itself from %s", [storage_object_name, field])
}

# SR-13. Installing a CSI driver installs a new means wholesale.
deny contains msg if {
  is_storage_object
  input.kind == "CSIDriver"
  not storage_object_name in enumerated_csi_drivers
  msg := sprintf("CSIDriver %s is outside the enumerated local-provisioner allowlist", [storage_object_name])
}

# SR-14. VolumeAttributesClass is the newest object that can point storage at a
# backend, so it is bound to the same driver enumeration.
deny contains msg if {
  is_storage_object
  input.kind == "VolumeAttributesClass"
  not object.get(input, "driverName", "") in enumerated_csi_drivers
  msg := sprintf("VolumeAttributesClass %s is outside the enumerated local-provisioner allowlist", [storage_object_name])
}

# SR-15. A volumeAttributesClassName is a REFERENCE, and a reference to a means
# is part of the means: storageClassName gets both object treatment (SR-9) and
# reference treatment (SR-7/SR-11), and this one had neither. The enumeration is
# empty, so every reference denies today — including one that names a class
# created out of band before this policy could refuse it.
deny contains msg if {
  is_storage_object
  input.kind in {"PersistentVolume", "PersistentVolumeClaim"}
  storage_spec_declares("volumeAttributesClassName")
  not object.get(storage_object_spec, "volumeAttributesClassName", "") in enumerated_volume_attributes_classes
  msg := sprintf("%s %s references a VolumeAttributesClass outside the enumerated allowlist", [input.kind, storage_object_name])
}

# SR-16. SR-10's rationale applied where it equally holds: mountOptions is where
# a remote endpoint is named, and `["addr=storage.invalid", "vers=4.1"]` is an NFS mount
# by another spelling. A statically provisioned local volume needs none.
deny contains msg if {
  is_storage_object
  input.kind == "PersistentVolume"
  storage_spec_declares("mountOptions")
  not empty_collection(object.get(storage_object_spec, "mountOptions", []))
  msg := sprintf("PersistentVolume %s must declare no mountOptions; that is where a remote endpoint would be named", [storage_object_name])
}

local_path_under_enumerated_root(path) if {
  is_string(path)
  some root in enumerated_local_volume_roots
  path == root
}

local_path_under_enumerated_root(path) if {
  is_string(path)
  some root in enumerated_local_volume_roots
  startswith(path, sprintf("%s/", [root]))
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
  count(pod_volume_sources(volume)) != 1
  msg := sprintf("volume %s must declare exactly one volume source, found %d", [pod_volume_name(volume), count(pod_volume_sources(volume))])
}

deny contains msg if {
  is_workload
  some volume in object.get(pod_spec, "volumes", [])
  some source in pod_volume_sources(volume)
  not source in admitted_pod_volume_sources
  msg := sprintf("volume %s uses undiscovered storage source %s", [pod_volume_name(volume), source])
}

pod_volume_sources(volume) := {field |
  some field, _ in volume
  not field in pod_volume_non_source_fields
}

pod_volume_name(volume) := name if {
  name := object.get(volume, "name", "")
  is_string(name)
  name != ""
} else := "<unnamed>"

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

# `volumes: null` is a STORED null, not an absent key: object.get returns that
# null rather than its default and `some volume in null` iterates nothing, so
# every volume denial above silently stops firing. This was the one fail-open
# shape in a 16-shape sweep.
# Refusing every non-list `volumes` here closes that divergence at the only
# place it can be closed without weakening anything: normalizing the field to
# an empty list instead would ALSO skip the walk of a map-shaped value, which
# `some volume in` does iterate today. Scoped to the exact tenant workload
# storage boundaries.
deny contains msg if {
  is_workload
  restricted_namespace
  not is_array(object.get(pod_spec, "volumes", []))
  msg := sprintf("%s %s/%s declares a non-list volumes field", [input.kind, input.metadata.namespace, input.metadata.name])
}

# Only the two reviewed connector Deployments may exist in cloudflare-public,
# so an invented third connector cannot claim a site's identity.
deny contains msg if {
  public_connector_deployment
  not object.get(input.metadata, "name", "") in connector_deployments
  msg := sprintf("Deployment cloudflare-public/%s is outside the reviewed connector inventory", [object.get(input.metadata, "name", "")])
}

# Every instance label a connector Deployment states must equal its own
# Deployment name, so the label the mount rule derives the token from cannot
# be restated by the caller (see connector_identity_rooted_in_name).
deny contains msg if {
  public_connector_deployment
  not connector_identity_rooted_in_name
  msg := sprintf("Deployment cloudflare-public/%s must state its own name as app.kubernetes.io/instance in its metadata labels, selector, and pod template; the connector identity tuple is rooted in the Deployment name", [object.get(input.metadata, "name", "")])
}

# The deployed token-delivery surface (env/secretKeyRef), bound to the same
# own-instance derivation the mounted-volume surface already uses. Scoped to
# every workload in cloudflare-public, not only to those that declare a
# secretKeyRef: a workload there that claims no reviewed connector identity
# has no legitimate way to name a connector's Secret at all, and requiring the
# identity first is what keeps the derivation from being satisfied by an
# absent label.
deny contains msg if {
  public_connector_workload
  not connector_secret_env_binding_is_own_instance
  msg := sprintf("%s cloudflare-public/%s may take its Tunnel token only from the Secret derived from its own app.kubernetes.io/instance, through env.valueFrom.secretKeyRef and never through envFrom", [input.kind, object.get(input.metadata, "name", "")])
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
  input.metadata.namespace == "flux-system"
  input.metadata.name == "default-deny"
  not valid_default_deny_policy
  msg := "NetworkPolicy flux-system/default-deny must isolate every Pod for ingress and egress"
}

# The regression this rule exists for: regenerating gotk-components.yaml
# without the allow-egress patch restores `egress: [{}]`, which would silently
# reopen every flux-system Pod to every destination.
deny contains msg if {
  input.kind == "NetworkPolicy"
  input.metadata.namespace == "flux-system"
  input.metadata.name in flux_generated_network_policies
  count(object.get(input.spec, "egress", [])) > 0
  msg := sprintf("NetworkPolicy flux-system/%s must carry no egress rule; the generated blanket allow is removed by patch", [input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkPolicy"
  input.metadata.namespace == "flux-system"
  not flux_network_policy_allowlisted
  msg := sprintf("NetworkPolicy flux-system/%s is outside the exact Flux controller DNS, artifact, public-HTTPS, and API-server egress allowlist", [input.metadata.name])
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

# The canonical publisher per tenant namespace, and the exact shape of the
# reference that names it. A reference may carry the published release tag in
# front of the digest — `repo:vMAJOR.MINOR.PATCH@sha256:...`, the form the
# connector and Flux images already use — so an operator reading
# `kubectl describe pod` sees which release is running. The tag is legibility
# only and is never what resolves: the `@sha256:` suffix stays MANDATORY and
# anchored, so safety invariant 6 is untouched and dropping the digest for a
# bare tag is still denied. The tag shape is closed to the site publishers'
# own SemVer form, so `:latest`, a branch name, or a second registry host
# cannot ride in through it. Repository hosts are now dot-escaped, which is
# strictly narrower than the unescaped literals this replaced.
deny contains msg if {
  is_workload
  restricted_namespace
  namespace := input.metadata.namespace
  expected_repository := {
    "naranjo-online": "ghcr[.]io/snaraj/naranjo-online(:v[0-9]+[.][0-9]+[.][0-9]+)?",
    "lidersea-com": "ghcr[.]io/snaraj/lidersea-com(:v[0-9]+[.][0-9]+[.][0-9]+)?",
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

# The coarse registry rule that covers every workload, tenant or platform.
# It is TIGHTER than the `.+` it replaces: the repository path and the optional
# release tag are each a closed character class, so a reference can no longer
# smuggle `/`, `@`, or a second `:` between the approved host prefix and the
# digest. The digest remains mandatory and anchored; the tag remains optional
# here because the exact per-namespace tag shape is pinned by the canonical
# repository rule above, and because the digest-only form must stay valid for
# a rollback pin that names no release.
approved_workload_image(image) if {
  regex.match("^(ghcr[.]io/(snaraj|fluxcd)/[A-Za-z0-9._/-]+(:[A-Za-z0-9._-]+)?|cloudflare/cloudflared:[A-Za-z0-9._-]+)@sha256:[0-9a-f]{64}$", image)
}

# One exact registry.k8s.io identity is admitted for the ephemeral API canary.
# Keeping it outside the coarse registry alternation means another Kubernetes
# image, another kubectl release, or even a different digest of this tag is not
# silently approved.
approved_workload_image(image) if {
  image == "registry.k8s.io/kubectl:v1.36.3@sha256:6e4fce3c83651edb91b74bc67701c5cd263dd8aa3cd4254b1798d6425a5ab789"
}

deny contains msg if {
  is_workload
  some container in containers
  not approved_workload_image(container.image)
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

# ---------------------------------------------------------------------------
# Flux controller authorization (AUDIT S12)
# ---------------------------------------------------------------------------
#
# The narrowing lives in Kustomize patches over a generated export, so the
# static checks in scripts/validate_repository.py can only prove the patches
# exist and are wired in. These rules run over the RENDERED output and prove
# the patches actually took effect: what the cluster would receive carries no
# cluster-admin binding, no wildcard rule bound to a Flux account, and no
# impersonation grant that is not restricted to named accounts.

# The two generated ClusterRoles that legitimately keep wildcards aggregate into
# the built-in admin/edit/view roles for human operators. They are harmless
# because nothing binds them, which is asserted below rather than assumed.
flux_aggregation_roles := {"flux-edit-flux-system", "flux-view-flux-system"}

# Namespaces whose Roles are part of the Flux authorization surface.
flux_rbac_namespaces := {"flux-system", "cloudflare-public", "naranjo-online", "lidersea-com"}

rbac_binding_kinds := {"RoleBinding", "ClusterRoleBinding"}

deny contains msg if {
  input.kind in rbac_binding_kinds
  object.get(object.get(input, "roleRef", {}), "name", "") == "cluster-admin"
  msg := sprintf("%s %s must not bind cluster-admin", [input.kind, input.metadata.name])
}

deny contains msg if {
  input.kind == "ClusterRoleBinding"
  input.metadata.name == "cluster-reconciler-flux-system"
  msg := "the cluster-admin reconciler binding must be deleted, not rendered"
}

deny contains msg if {
  input.kind in rbac_binding_kinds
  object.get(object.get(input, "roleRef", {}), "name", "") in flux_aggregation_roles
  msg := sprintf("%s %s must not bind a wildcard aggregation role", [input.kind, input.metadata.name])
}

deny contains msg if {
  input.kind == "ClusterRole"
  not input.metadata.name in flux_aggregation_roles
  some rule in object.get(input, "rules", [])
  some field in {"apiGroups", "resources", "verbs"}
  "*" in object.get(rule, field, [])
  msg := sprintf("ClusterRole %s must not grant a wildcard %s", [input.metadata.name, field])
}

deny contains msg if {
  input.kind == "Role"
  input.metadata.namespace in flux_rbac_namespaces
  some rule in object.get(input, "rules", [])
  some field in {"apiGroups", "resources", "verbs"}
  "*" in object.get(rule, field, [])
  msg := sprintf("Role %s/%s must not grant a wildcard %s", [input.metadata.namespace, input.metadata.name, field])
}

# Impersonation is the mechanism that replaced cluster-admin, so it is the one
# verb whose scope must always be an explicit list of accounts.
deny contains msg if {
  input.kind in {"Role", "ClusterRole"}
  some rule in object.get(input, "rules", [])
  "impersonate" in object.get(rule, "verbs", [])
  count(object.get(rule, "resourceNames", [])) == 0
  msg := sprintf("%s %s must restrict impersonate to named accounts", [input.kind, input.metadata.name])
}

deny contains msg if {
  input.kind == "ClusterRole"
  some rule in object.get(input, "rules", [])
  "impersonate" in object.get(rule, "verbs", [])
  msg := sprintf("ClusterRole %s must not grant impersonate at cluster scope", [input.metadata.name])
}

# Token minting is escalation to any account in the cluster; this platform
# authenticates to no cloud provider and needs it nowhere.
deny contains msg if {
  input.kind in {"Role", "ClusterRole"}
  some rule in object.get(input, "rules", [])
  "serviceaccounts/token" in object.get(rule, "resources", [])
  msg := sprintf("%s %s must not grant ServiceAccount token creation", [input.kind, input.metadata.name])
}

# The controllers read the SOPS age key in flux-system and write no Secret
# anywhere; a write verb there would let a controller replace the key it
# decrypts with.
deny contains msg if {
  input.kind == "Role"
  input.metadata.namespace == "flux-system"
  some rule in object.get(input, "rules", [])
  "secrets" in object.get(rule, "resources", [])
  some verb in object.get(rule, "verbs", [])
  verb in {"create", "update", "patch", "delete", "deletecollection"}
  msg := sprintf("Role flux-system/%s must not write Secrets", [input.metadata.name])
}

valid_flux_decryption_role if {
  object.get(input, "rules", []) == [{
    "apiGroups": [""],
    "resources": ["secrets"],
    "resourceNames": ["sops-age"],
    "verbs": ["get"],
  }]
}

deny contains msg if {
  input.kind == "Role"
  input.metadata.namespace == "flux-system"
  input.metadata.name == "flux-controller-decryption"
  not valid_flux_decryption_role
  msg := "Role flux-system/flux-controller-decryption must grant only exact sops-age Secret get"
}

# Optional ConfigMap/Secret watchers are disabled on both reconcilers. Helm
# release storage uses the impersonated tenant reconciler, so no controller
# ClusterRole needs cluster-wide Secret access.
deny contains msg if {
  input.kind == "ClusterRole"
  some rule in object.get(input, "rules", [])
  "secrets" in object.get(rule, "resources", [])
  msg := sprintf("ClusterRole %s must not grant cluster-wide Secret access", [input.metadata.name])
}

# No controller needs to write a Secret under its own identity, and a write verb
# here would enable credential mutation across every namespace. Keep this
# independent denial so an attempted widening names both the cluster-scope read
# and credential-mutation authority.
deny contains msg if {
  input.kind == "ClusterRole"
  some rule in object.get(input, "rules", [])
  "secrets" in object.get(rule, "resources", [])
  some verb in object.get(rule, "verbs", [])
  verb in {"create", "update", "patch", "delete", "deletecollection"}
  msg := sprintf("ClusterRole %s must not write Secrets", [input.metadata.name])
}

# The shared controller ClusterRoleBinding must name the ServiceAccounts this
# install creates and nothing else: a subject for an uninstalled controller
# activates silently the day that controller arrives.
deny contains msg if {
  input.kind == "ClusterRoleBinding"
  input.metadata.name == "crd-controller-flux-system"
  subjects := {sprintf("%s/%s", [subject.namespace, subject.name]) | some subject in object.get(input, "subjects", [])}
  subjects != {"flux-system/source-controller", "flux-system/kustomize-controller", "flux-system/helm-controller"}
  msg := "crd-controller-flux-system must bind exactly the three installed controllers"
}

# THE PER-CONTROLLER SPLIT (issue #98), enforced over the rendered output.
# These rules are additive defence in depth beside the fast structural validator,
# RBAC model, and live-state mirror; they replace none of those independent gates.
#
# `crd-controller-flux-system` is the one ClusterRole bound to all three
# controllers, so any Flux API group it names is authority each controller holds
# over the OTHER two's reconciliation specifications: rewriting or unsuspending
# another controller's execution object gets it applied BY that controller,
# under whichever account it impersonates, which impersonation cannot contain.
# The rule is verb-agnostic on purpose — a read shared this way is harmless, but
# the shared role has no reason to carry one now that each controller's own role
# does, and a verb-scoped rule would need updating the day a new verb mattered.
flux_execution_api_groups := {
  "source.toolkit.fluxcd.io",
  "kustomize.toolkit.fluxcd.io",
  "helm.toolkit.fluxcd.io",
}

deny contains msg if {
  input.kind == "ClusterRole"
  input.metadata.name == "crd-controller-flux-system"
  some rule in object.get(input, "rules", [])
  some group in object.get(rule, "apiGroups", [])
  group in flux_execution_api_groups
  msg := sprintf("ClusterRole crd-controller-flux-system is bound to all three controllers and must not grant %s", [group])
}

# Each controller's own authority lives in its own ClusterRole, bound to exactly
# one ServiceAccount. A second subject on one of these rebuilds the shared role
# under a new name with every rule still reading correctly, so the subject set is
# pinned rather than merely required to contain its owner.
per_controller_cluster_roles := {
  "crd-controller-source-flux-system": "source-controller",
  "crd-controller-kustomize-flux-system": "kustomize-controller",
  "crd-controller-helm-flux-system": "helm-controller",
}

deny contains msg if {
  input.kind == "ClusterRoleBinding"
  owner := per_controller_cluster_roles[input.metadata.name]
  subjects := {sprintf("%s/%s", [subject.namespace, subject.name]) | some subject in object.get(input, "subjects", [])}
  subjects != {sprintf("flux-system/%s", [owner])}
  msg := sprintf("ClusterRoleBinding %s must bind only flux-system/%s", [input.metadata.name, owner])
}

# And it must bind the role it is named for. A per-controller binding repointed
# at another controller's role passes the subject check above while handing that
# controller the other one's authority.
deny contains msg if {
  input.kind == "ClusterRoleBinding"
  per_controller_cluster_roles[input.metadata.name]
  object.get(input, "roleRef", {}).name != input.metadata.name
  msg := sprintf("ClusterRoleBinding %s must bind ClusterRole %s", [input.metadata.name, input.metadata.name])
}

valid_kustomize_secondary_source_rules if {
  source_rules := [rule |
    some rule in object.get(input, "rules", [])
    "source.toolkit.fluxcd.io" in object.get(rule, "apiGroups", [])
  ]
  source_rules == [{
    "apiGroups": ["source.toolkit.fluxcd.io"],
    "resources": ["buckets", "gitrepositories", "ocirepositories"],
    "verbs": ["get", "list", "watch"],
  }]
}

deny contains msg if {
  input.kind == "ClusterRole"
  input.metadata.name == "crd-controller-kustomize-flux-system"
  not valid_kustomize_secondary_source_rules
  msg := "ClusterRole crd-controller-kustomize-flux-system must grant only exact read-only Bucket, GitRepository, and OCIRepository secondary watches"
}

valid_helm_source_rules if {
  source_rules := [rule |
    some rule in object.get(input, "rules", [])
    "source.toolkit.fluxcd.io" in object.get(rule, "apiGroups", [])
  ]
  count(source_rules) == 2
  some chart_rule in source_rules
  chart_rule == {
    "apiGroups": ["source.toolkit.fluxcd.io"],
    "resources": ["helmcharts"],
    "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
  }
  some oci_rule in source_rules
  oci_rule == {
    "apiGroups": ["source.toolkit.fluxcd.io"],
    "resources": ["ocirepositories"],
    "verbs": ["get", "list", "watch"],
  }
}

deny contains msg if {
  input.kind == "ClusterRole"
  input.metadata.name == "crd-controller-helm-flux-system"
  not valid_helm_source_rules
  msg := "ClusterRole crd-controller-helm-flux-system must grant exact HelmChart lifecycle and read-only OCIRepository secondary watch authority"
}
