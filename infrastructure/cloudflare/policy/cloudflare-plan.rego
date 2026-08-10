package main

import rego.v1

# Every state root has one exact graph. The phase is injected by
# scripts/cloudflare-plan-gate.sh; it is not an operator-controlled tfvar.
valid_phases := {
  "admin-tunnel",
  "admin-policies",
  "admin-route",
  "admin-api",
  "public-edge",
  "public-dns-naranjo",
  "public-dns-lidersea",
}

cloudflared_tunnel_resource_type := "cloudflare_zero_trust_tunnel_cloudflared"

expected_types := {
  "admin-tunnel": {
    "cloudflare_zero_trust_tunnel_cloudflared.pi_admin": cloudflared_tunnel_resource_type,
  },
  "admin-policies": {
    "cloudflare_zero_trust_gateway_policy.pi_admin_block": "cloudflare_zero_trust_gateway_policy",
    "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow": "cloudflare_zero_trust_gateway_policy",
  },
  "admin-route": {
    "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin": "cloudflare_zero_trust_tunnel_cloudflared_route",
  },
  "admin-api": {
    "cloudflare_zero_trust_gateway_policy.pi_admin_api_allow": "cloudflare_zero_trust_gateway_policy",
  },
  "public-edge": {
    "cloudflare_zero_trust_tunnel_cloudflared.pi_websites": cloudflared_tunnel_resource_type,
    "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites": "cloudflare_zero_trust_tunnel_cloudflared_config",
  },
  "public-dns-naranjo": {
    "cloudflare_dns_record.naranjo_online": "cloudflare_dns_record",
  },
  "public-dns-lidersea": {
    "cloudflare_dns_record.lidersea_com": "cloudflare_dns_record",
  },
}

approval_variables := {
  "admin-tunnel": "approve_admin_tunnel_phase",
  "admin-policies": "approve_admin_policies_phase",
  "admin-route": "approve_admin_route_phase",
  "admin-api": "enable_kubernetes_api_access",
  "public-edge": "approve_public_edge_phase",
  "public-dns-naranjo": "enable_public_dns_naranjo_activation",
  "public-dns-lidersea": "enable_public_dns_lidersea_activation",
}

expected_expression_fields := {
  "cloudflare_zero_trust_tunnel_cloudflared.pi_admin": {"account_id", "name", "config_src"},
  "cloudflare_zero_trust_gateway_policy.pi_admin_block": {"account_id", "name", "description", "action", "enabled", "filters", "precedence", "traffic"},
  "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow": {"account_id", "name", "description", "action", "enabled", "filters", "precedence", "traffic", "identity", "device_posture", "rule_settings"},
  "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin": {"account_id", "tunnel_id", "network", "comment"},
  "cloudflare_zero_trust_gateway_policy.pi_admin_api_allow": {"account_id", "name", "description", "action", "enabled", "filters", "precedence", "traffic", "identity", "device_posture", "rule_settings"},
  "cloudflare_zero_trust_tunnel_cloudflared.pi_websites": {"account_id", "name", "config_src"},
  "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites": {"account_id", "tunnel_id", "source", "config"},
  "cloudflare_dns_record.naranjo_online": {"zone_id", "name", "type", "content", "proxied", "ttl"},
  "cloudflare_dns_record.lidersea_com": {"zone_id", "name", "type", "content", "proxied", "ttl"},
}

critical_fields := {
  "cloudflare_zero_trust_tunnel_cloudflared": {"account_id", "name", "config_src"},
  "cloudflare_zero_trust_tunnel_cloudflared_route": {"account_id", "tunnel_id", "network", "comment"},
  "cloudflare_zero_trust_tunnel_cloudflared_config": {"account_id", "source", "config"},
  "cloudflare_zero_trust_gateway_policy": {
    "account_id", "name", "action", "enabled", "filters", "precedence",
    "traffic", "identity", "device_posture", "rule_settings",
  },
  "cloudflare_dns_record": {"zone_id", "name", "type", "content", "proxied", "ttl"},
}

canonical_naranjo_online_hostname := "naranjo.online"
canonical_naranjo_online_origin := "http://naranjo-online.naranjo-online.svc.cluster.local:8080"
canonical_lidersea_com_hostname := "lidersea.com"
canonical_lidersea_com_origin := "http://lidersea-com.lidersea-com.svc.cluster.local:8080"

phase := object.get(object.get(input, "codex_contract", {}), "phase", "")

managed_changes := [change |
  some change in object.get(input, "resource_changes", [])
  object.get(change, "mode", "managed") == "managed"
]

configured_managed := [resource |
  some resource in object.get(
    object.get(object.get(input, "configuration", {}), "root_module", {}),
    "resources",
    [],
  )
  object.get(resource, "mode", "managed") == "managed"
]

configured_data := [resource |
  some resource in object.get(
    object.get(object.get(input, "configuration", {}), "root_module", {}),
    "resources",
    [],
  )
  object.get(resource, "mode", "managed") == "data"
]

planned_data := [change |
  some change in object.get(input, "resource_changes", [])
  object.get(change, "mode", "managed") == "data"
]

root_configuration := object.get(
  object.get(input, "configuration", {}),
  "root_module",
  {},
)

configured_module_calls := object.get(root_configuration, "module_calls", {})
configured_providers := object.get(
  object.get(input, "configuration", {}),
  "provider_config",
  {},
)

actual_addresses := {change.address | some change in managed_changes}
configured_addresses := {resource.address | some resource in configured_managed}

variable_value(name) := value if {
  value := input.variables[name].value
}

change_after(address) := after if {
  some change in managed_changes
  change.address == address
  after := change.change.after
}

configuration_resource(address) := resource if {
  some resource in configured_managed
  resource.address == address
}

has_exact_reference(address, field, expected) if {
  resource := configuration_resource(address)
  references := object.get(object.get(resource.expressions, field, {}), "references", [])
  references == [expected]
}

reference_in_id_tree(reference, root) if {
  reference == root
}

reference_in_id_tree(reference, root) if {
  reference == sprintf("%s.id", [root])
}

has_only_id_tree(address, field, root) if {
  resource := configuration_resource(address)
  references := object.get(object.get(resource.expressions, field, {}), "references", [])
  root in references
  sprintf("%s.id", [root]) in references
  every reference in references {
    reference_in_id_tree(reference, root)
  }
}

valid_account_id(identifier) if {
  regex.match(`^[0-9a-f]{32}$`, identifier)
  regex.match(`[1-9a-f]`, identifier)
}

valid_uuid(identifier) if {
  regex.match(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, identifier)
}

# Repository fixtures use the one privacy-approved nil UUID. Terraform input
# validation still rejects it in every live phase root.
valid_uuid("00000000-0000-0000-0000-000000000000")

valid_contract_hash(value) if {
  regex.match(`^[0-9a-f]{64}$`, value)
  regex.match(`[1-9a-f]`, value)
}

private_ipv4_32(network) if {
  regex.match(`^[0-9.]+/32$`, network)
  net.cidr_contains("10.0.0.0/8", network)
}

private_ipv4_32(network) if {
  regex.match(`^[0-9.]+/32$`, network)
  net.cidr_contains("172.16.0.0/12", network)
}

private_ipv4_32(network) if {
  regex.match(`^[0-9.]+/32$`, network)
  net.cidr_contains("192.168.0.0/16", network)
}

valid_session_duration(duration) if {
  regex.match(`^[1-9][0-9]*s$`, duration)
  to_number(trim_suffix(duration, "s")) <= 900
}

absent_text(value) if {
  value == null
}

absent_text(value) if {
  value == ""
}

absent_settings(value) if {
  value == null
}

absent_settings(value) if {
  value == {}
}

exact_session(policy, duration) if {
  session := policy.rule_settings.check_session
  object.keys(policy.rule_settings) == {"check_session"}
  object.keys(session) == {"enforce", "duration"}
  session.enforce == true
  session.duration == duration
  valid_session_duration(duration)
}

exact_identity_policy(policy, network, port, email, posture_id, duration) if {
  regex.match(`^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$`, email)
  valid_uuid(posture_id)
  policy.action == "allow"
  policy.enabled == true
  policy.filters == ["l4"]
  policy.traffic == sprintf(`net.dst.ip in {%s} and net.protocol == "tcp" and net.dst.port in {%d}`, [network, port])
  policy.identity == sprintf(`identity.email == "%s"`, [email])
  policy.device_posture == sprintf(`any(device_posture.checks.passed[*] in {"%s"})`, [posture_id])
  exact_session(policy, duration)
  absent_text(object.get(policy, "expiration", null))
  absent_text(object.get(policy, "schedule", null))
}

account_matches(after) if {
  account_id := variable_value("cloudflare_account_id")
  valid_account_id(account_id)
  after.account_id == account_id
}

admin_tunnel_exact if {
  tunnel := change_after("cloudflare_zero_trust_tunnel_cloudflared.pi_admin")
  account_matches(tunnel)
  tunnel.name == "pi-admin"
  tunnel.config_src == "cloudflare"
  object.get(tunnel, "tunnel_secret", null) == null
  has_exact_reference("cloudflare_zero_trust_tunnel_cloudflared.pi_admin", "account_id", "var.cloudflare_account_id")
}

admin_policies_exact if {
  network := variable_value("pi_admin_cidr")
  email := variable_value("admin_email")
  posture_id := variable_value("admin_device_posture_check_id")
  duration := variable_value("admin_session_freshness")
  private_ipv4_32(network)
  valid_uuid(variable_value("pi_admin_tunnel_id"))
  valid_contract_hash(variable_value("verified_admin_tunnel_contract_sha256"))
  valid_contract_hash(variable_value("verified_admin_posture_contract_sha256"))
  valid_contract_hash(variable_value("verified_admin_policy_inputs_contract_sha256"))

  block := change_after("cloudflare_zero_trust_gateway_policy.pi_admin_block")
  account_matches(block)
  block.name == "pi-admin-block"
  block.action == "block"
  block.enabled == true
  block.filters == ["l4"]
  block.precedence == variable_value("pi_admin_block_precedence")
  block.traffic == sprintf("net.dst.ip in {%s}", [network])
  absent_text(object.get(block, "identity", null))
  absent_text(object.get(block, "device_posture", null))
  absent_settings(object.get(block, "rule_settings", null))
  absent_text(object.get(block, "expiration", null))
  absent_text(object.get(block, "schedule", null))

  ssh := change_after("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow")
  account_matches(ssh)
  ssh.name == "pi-admin-ssh-allow"
  exact_identity_policy(ssh, network, 22, email, posture_id, duration)
  ssh.precedence == variable_value("pi_admin_ssh_allow_precedence")
  ssh.precedence < block.precedence

  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_block", "account_id", "var.cloudflare_account_id")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_block", "precedence", "var.pi_admin_block_precedence")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_block", "traffic", "var.pi_admin_cidr")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow", "account_id", "var.cloudflare_account_id")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow", "precedence", "var.pi_admin_ssh_allow_precedence")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow", "traffic", "var.pi_admin_cidr")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow", "identity", "var.admin_email")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow", "device_posture", "var.admin_device_posture_check_id")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow", "rule_settings", "var.admin_session_freshness")
}

admin_route_exact if {
  route := change_after("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin")
  account_matches(route)
  network := variable_value("pi_admin_cidr")
  tunnel_id := variable_value("pi_admin_tunnel_id")
  private_ipv4_32(network)
  valid_uuid(tunnel_id)
  regex.match(`^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$`, variable_value("admin_email"))
  valid_uuid(variable_value("admin_device_posture_check_id"))
  valid_contract_hash(variable_value("verified_admin_posture_contract_sha256"))
  valid_session_duration(variable_value("admin_session_freshness"))
  variable_value("pi_admin_ssh_allow_precedence") < variable_value("pi_admin_block_precedence")
  route.network == network
  route.tunnel_id == tunnel_id
  route.comment == "Pi host only; verified block and SSH-only allow required"
  valid_contract_hash(variable_value("verified_admin_policies_contract_sha256"))
  has_exact_reference("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin", "account_id", "var.cloudflare_account_id")
  has_exact_reference("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin", "network", "var.pi_admin_cidr")
  has_exact_reference("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin", "tunnel_id", "var.pi_admin_tunnel_id")
}

admin_api_exact if {
  policy := change_after("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow")
  account_matches(policy)
  network := variable_value("pi_admin_cidr")
  email := variable_value("admin_email")
  posture_id := variable_value("admin_device_posture_check_id")
  duration := variable_value("admin_session_freshness")
  private_ipv4_32(network)
  valid_uuid(variable_value("pi_admin_tunnel_id"))
  valid_contract_hash(variable_value("verified_admin_posture_contract_sha256"))
  valid_contract_hash(variable_value("verified_admin_policies_contract_sha256"))
  valid_contract_hash(variable_value("verified_admin_route_contract_sha256"))
  valid_contract_hash(variable_value("verified_admin_api_inputs_contract_sha256"))
  policy.name == "pi-admin-api-allow"
  exact_identity_policy(policy, network, 6443, email, posture_id, duration)
  policy.precedence == variable_value("pi_admin_api_allow_precedence")
  variable_value("pi_admin_ssh_allow_precedence") < policy.precedence
  policy.precedence < variable_value("pi_admin_block_precedence")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow", "account_id", "var.cloudflare_account_id")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow", "precedence", "var.pi_admin_api_allow_precedence")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow", "traffic", "var.pi_admin_cidr")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow", "identity", "var.admin_email")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow", "device_posture", "var.admin_device_posture_check_id")
  has_exact_reference("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow", "rule_settings", "var.admin_session_freshness")
}

public_edge_exact if {
  tunnel := change_after("cloudflare_zero_trust_tunnel_cloudflared.pi_websites")
  account_matches(tunnel)
  tunnel.name == "pi-websites"
  tunnel.config_src == "cloudflare"
  object.get(tunnel, "tunnel_secret", null) == null

  edge := change_after("cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites")
  account_matches(edge)
  edge.source == "cloudflare"
  object.keys(edge.config) == {"ingress"}
  ingress := edge.config.ingress
  count(ingress) == 3
  ingress[0] == {"hostname": canonical_naranjo_online_hostname, "service": canonical_naranjo_online_origin}
  ingress[1] == {"hostname": canonical_lidersea_com_hostname, "service": canonical_lidersea_com_origin}
  ingress[2] == {"service": "http_status:404"}

  has_exact_reference("cloudflare_zero_trust_tunnel_cloudflared.pi_websites", "account_id", "var.cloudflare_account_id")
  has_exact_reference("cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites", "account_id", "var.cloudflare_account_id")
  has_only_id_tree(
    "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites",
    "tunnel_id",
    "cloudflare_zero_trust_tunnel_cloudflared.pi_websites",
  )
}

exact_dns_record(record, hostname, zone_id, tunnel_id) if {
  record.name == hostname
  record.zone_id == zone_id
  record.type == "CNAME"
  record.content == sprintf("%s.cfargotunnel.com", [tunnel_id])
  record.proxied == true
  record.ttl == 1
}

public_dns_naranjo_exact if {
  account_id := variable_value("cloudflare_account_id")
  naranjo_zone := variable_value("cloudflare_naranjo_online_zone_id")
  tunnel_id := variable_value("pi_websites_tunnel_id")
  valid_account_id(account_id)
  valid_account_id(naranjo_zone)
  valid_uuid(tunnel_id)
  account_id != naranjo_zone
  valid_contract_hash(variable_value("verified_public_edge_contract_sha256"))

  naranjo := change_after("cloudflare_dns_record.naranjo_online")
  exact_dns_record(naranjo, canonical_naranjo_online_hostname, naranjo_zone, tunnel_id)
  has_exact_reference("cloudflare_dns_record.naranjo_online", "zone_id", "var.cloudflare_naranjo_online_zone_id")
  has_exact_reference("cloudflare_dns_record.naranjo_online", "content", "var.pi_websites_tunnel_id")
}

public_dns_lidersea_exact if {
  account_id := variable_value("cloudflare_account_id")
  lidersea_zone := variable_value("cloudflare_lidersea_com_zone_id")
  tunnel_id := variable_value("pi_websites_tunnel_id")
  valid_account_id(account_id)
  valid_account_id(lidersea_zone)
  valid_uuid(tunnel_id)
  account_id != lidersea_zone
  valid_contract_hash(variable_value("verified_public_edge_contract_sha256"))

  lidersea := change_after("cloudflare_dns_record.lidersea_com")
  exact_dns_record(lidersea, canonical_lidersea_com_hostname, lidersea_zone, tunnel_id)
  has_exact_reference("cloudflare_dns_record.lidersea_com", "zone_id", "var.cloudflare_lidersea_com_zone_id")
  has_exact_reference("cloudflare_dns_record.lidersea_com", "content", "var.pi_websites_tunnel_id")
}

phase_contract_exact if {
  phase == "admin-tunnel"
  admin_tunnel_exact
}

phase_contract_exact if {
  phase == "admin-policies"
  admin_policies_exact
}

phase_contract_exact if {
  phase == "admin-route"
  admin_route_exact
}

phase_contract_exact if {
  phase == "admin-api"
  admin_api_exact
}

phase_contract_exact if {
  phase == "public-edge"
  public_edge_exact
}

phase_contract_exact if {
  phase == "public-dns-naranjo"
  public_dns_naranjo_exact
}

phase_contract_exact if {
  phase == "public-dns-lidersea"
  public_dns_lidersea_exact
}

deny contains "missing or unknown Cloudflare phase contract" if {
  not phase in valid_phases
}

deny contains msg if {
  phase in valid_phases
  expected := object.keys(expected_types[phase])
  actual_addresses != expected
  msg := sprintf("%s managed graph must exactly equal %v", [phase, expected])
}

deny contains msg if {
  phase in valid_phases
  expected := object.keys(expected_types[phase])
  configured_addresses != expected
  msg := sprintf("%s configuration graph must exactly equal %v", [phase, expected])
}

deny contains msg if {
  phase in valid_phases
  some change in managed_changes
  change.type != expected_types[phase][change.address]
  msg := sprintf("resource type/address mismatch: %s", [change.address])
}

deny contains msg if {
  phase in valid_phases
  some resource in configured_managed
  resource.type != expected_types[phase][resource.address]
  msg := sprintf("configured type/address mismatch: %s", [resource.address])
}

deny contains msg if {
  phase in valid_phases
  some resource in configured_managed
  object.keys(object.get(resource, "expressions", {})) != expected_expression_fields[resource.address]
  msg := sprintf("configured argument fields are not exact: %s", [resource.address])
}

deny contains msg if {
  some change in managed_changes
  "delete" in change.change.actions
  msg := sprintf("destruction is blocked: %s", [change.address])
}

deny contains msg if {
  some change in object.get(input, "resource_changes", [])
  object.get(change, "mode", "managed") != "managed"
  msg := sprintf("non-managed plan objects are forbidden: %s", [change.address])
}

deny contains msg if {
  some resource in object.get(root_configuration, "resources", [])
  object.get(resource, "mode", "managed") != "managed"
  msg := sprintf("non-managed configuration objects are forbidden: %s", [resource.address])
}

deny contains msg if {
  some change in managed_changes
  change.change.actions != ["create"]
  msg := sprintf("initial activation plans must contain create actions only: %s", [change.address])
}

deny contains msg if {
  some change in managed_changes
  object.get(change.change, "before", null) != null
  msg := sprintf("initial activation plans must have no prior object: %s", [change.address])
}

deny contains msg if {
  some change in planned_data
  msg := sprintf("all data sources are forbidden in closed Cloudflare roots: %s", [change.address])
}

deny contains msg if {
  some resource in configured_data
  msg := sprintf("all data sources are forbidden in closed Cloudflare configuration: %s", [resource.address])
}

deny contains "module calls are forbidden in closed Cloudflare roots" if {
  count(configured_module_calls) != 0
}

deny contains msg if {
  some resource in configured_managed
  count(object.get(resource, "provisioners", [])) != 0
  msg := sprintf("provisioners are forbidden in closed Cloudflare roots: %s", [resource.address])
}

deny contains "Cloudflare provider configuration is not the one empty environment-authenticated provider" if {
  count(configured_providers) != 1
}

deny contains "Cloudflare provider configuration is not the one empty environment-authenticated provider" if {
  some name, provider in configured_providers
  name != "cloudflare"
}

deny contains "Cloudflare provider configuration is not the one empty environment-authenticated provider" if {
  some provider_name, provider in configured_providers
  object.get(provider, "full_name", "") != "registry.opentofu.org/cloudflare/cloudflare"
}

deny contains "Cloudflare provider configuration is not the one empty environment-authenticated provider" if {
  some provider_name, provider in configured_providers
  count(object.get(provider, "expressions", {})) != 0
}

deny contains msg if {
  phase in valid_phases
  approval_name := approval_variables[phase]
  object.get(object.get(object.get(input, "variables", {}), approval_name, {}), "value", false) != true
  msg := sprintf("phase acknowledgement must be true: %s", [approval_name])
}

deny contains msg if {
  some change in managed_changes
  some field in object.get(critical_fields, change.type, {})
  object.get(object.get(change.change, "after_unknown", {}), field, false) != false
  msg := sprintf("critical field is unknown for %s: %s", [change.address, field])
}

deny contains msg if {
  phase in valid_phases
  not phase_contract_exact
  msg := sprintf("%s values or references violate the exact phase contract", [phase])
}
