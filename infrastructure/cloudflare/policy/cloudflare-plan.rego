package main

import rego.v1

# Every state root has one exact graph. The phase is injected by
# scripts/cloudflare-plan-gate.sh; it is not an operator-controlled tfvar.
valid_phases := {
  "admin-tunnel",
  "admin-policies",
  "admin-route",
  "admin-api",
  "site-naranjo-online",
  "site-lidersea-com",
}

# Administrative onboarding is create-only. The two public site roots ADOPT
# live objects that already serve traffic: a plan that would create, delete, or
# replace one of them is a hard stop, never an activation.
create_only_phases := {
  "admin-tunnel",
  "admin-policies",
  "admin-route",
  "admin-api",
}

# One site, one root, one state, one token, one blast radius. `foreign_marker`
# is the other site's identity token; it must never appear anywhere in this
# root's plan values or configuration references.
site_contracts := {
  "site-naranjo-online": {
    "slug": "naranjo_online",
    "tunnel_name": "naranjo-online",
    "hostname": "naranjo.online",
    "origin": "http://naranjo-online.naranjo-online.svc.cluster.local:8080",
    "zone_variable": "cloudflare_naranjo_online_zone_id",
    "audit_variable": "verified_naranjo_online_adoption_audit_sha256",
    "foreign_marker": "lidersea",
  },
  "site-lidersea-com": {
    "slug": "lidersea_com",
    "tunnel_name": "lidersea-com",
    "hostname": "lidersea.com",
    "origin": "http://lidersea-com.lidersea-com.svc.cluster.local:8080",
    "zone_variable": "cloudflare_lidersea_com_zone_id",
    "audit_variable": "verified_lidersea_com_adoption_audit_sha256",
    "foreign_marker": "naranjo",
  },
}

adopt_only_phases := object.keys(site_contracts)

# The zone security target state, encoded once. `ssl` is deliberately "full"
# and never a strict variant: the connector-to-origin leg is plain HTTP by
# accepted decision, so strict origin pull would break the site, not harden it.
zone_setting_contracts := {
  "always_use_https": {"setting_id": "always_use_https", "value": "on"},
  "min_tls_version": {"setting_id": "min_tls_version", "value": "1.2"},
  "tls_1_3": {"setting_id": "tls_1_3", "value": "on"},
  "zero_rtt": {"setting_id": "0rtt", "value": "off"},
  "ssl": {"setting_id": "ssl", "value": "full"},
}

# Identity objects that already exist live: a plan may confirm them, never
# change them. Ingress configuration and zone settings may legitimately move to
# the exact committed target, so they accept an update.
adopted_identity_types := {
  "cloudflare_zero_trust_tunnel_cloudflared",
  "cloudflare_dns_record",
}

forbidden_dns_record_types := {"A", "AAAA"}

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
  "site-naranjo-online": {
    "cloudflare_zero_trust_tunnel_cloudflared.naranjo_online": cloudflared_tunnel_resource_type,
    "cloudflare_zero_trust_tunnel_cloudflared_config.naranjo_online": "cloudflare_zero_trust_tunnel_cloudflared_config",
    "cloudflare_dns_record.naranjo_online_apex": "cloudflare_dns_record",
    "cloudflare_zone_setting.naranjo_online_always_use_https": "cloudflare_zone_setting",
    "cloudflare_zone_setting.naranjo_online_min_tls_version": "cloudflare_zone_setting",
    "cloudflare_zone_setting.naranjo_online_tls_1_3": "cloudflare_zone_setting",
    "cloudflare_zone_setting.naranjo_online_zero_rtt": "cloudflare_zone_setting",
    "cloudflare_zone_setting.naranjo_online_ssl": "cloudflare_zone_setting",
  },
  "site-lidersea-com": {
    "cloudflare_zero_trust_tunnel_cloudflared.lidersea_com": cloudflared_tunnel_resource_type,
    "cloudflare_zero_trust_tunnel_cloudflared_config.lidersea_com": "cloudflare_zero_trust_tunnel_cloudflared_config",
    "cloudflare_dns_record.lidersea_com_apex": "cloudflare_dns_record",
    "cloudflare_zone_setting.lidersea_com_always_use_https": "cloudflare_zone_setting",
    "cloudflare_zone_setting.lidersea_com_min_tls_version": "cloudflare_zone_setting",
    "cloudflare_zone_setting.lidersea_com_tls_1_3": "cloudflare_zone_setting",
    "cloudflare_zone_setting.lidersea_com_zero_rtt": "cloudflare_zone_setting",
    "cloudflare_zone_setting.lidersea_com_ssl": "cloudflare_zone_setting",
  },
}

approval_variables := {
  "admin-tunnel": "approve_admin_tunnel_phase",
  "admin-policies": "approve_admin_policies_phase",
  "admin-route": "approve_admin_route_phase",
  "admin-api": "enable_kubernetes_api_access",
  "site-naranjo-online": "approve_site_naranjo_online_phase",
  "site-lidersea-com": "approve_site_lidersea_com_phase",
}

expected_expression_fields := {
  "cloudflare_zero_trust_tunnel_cloudflared.pi_admin": {"account_id", "name", "config_src"},
  "cloudflare_zero_trust_gateway_policy.pi_admin_block": {"account_id", "name", "description", "action", "enabled", "filters", "precedence", "traffic"},
  "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow": {"account_id", "name", "description", "action", "enabled", "filters", "precedence", "traffic", "identity", "device_posture", "rule_settings"},
  "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin": {"account_id", "tunnel_id", "network", "comment"},
  "cloudflare_zero_trust_gateway_policy.pi_admin_api_allow": {"account_id", "name", "description", "action", "enabled", "filters", "precedence", "traffic", "identity", "device_posture", "rule_settings"},
  "cloudflare_zero_trust_tunnel_cloudflared.naranjo_online": {"account_id", "name", "config_src"},
  "cloudflare_zero_trust_tunnel_cloudflared_config.naranjo_online": {"account_id", "tunnel_id", "source", "config"},
  "cloudflare_dns_record.naranjo_online_apex": {"zone_id", "name", "type", "content", "proxied", "ttl"},
  "cloudflare_zone_setting.naranjo_online_always_use_https": {"zone_id", "setting_id", "value"},
  "cloudflare_zone_setting.naranjo_online_min_tls_version": {"zone_id", "setting_id", "value"},
  "cloudflare_zone_setting.naranjo_online_tls_1_3": {"zone_id", "setting_id", "value"},
  "cloudflare_zone_setting.naranjo_online_zero_rtt": {"zone_id", "setting_id", "value"},
  "cloudflare_zone_setting.naranjo_online_ssl": {"zone_id", "setting_id", "value"},
  "cloudflare_zero_trust_tunnel_cloudflared.lidersea_com": {"account_id", "name", "config_src"},
  "cloudflare_zero_trust_tunnel_cloudflared_config.lidersea_com": {"account_id", "tunnel_id", "source", "config"},
  "cloudflare_dns_record.lidersea_com_apex": {"zone_id", "name", "type", "content", "proxied", "ttl"},
  "cloudflare_zone_setting.lidersea_com_always_use_https": {"zone_id", "setting_id", "value"},
  "cloudflare_zone_setting.lidersea_com_min_tls_version": {"zone_id", "setting_id", "value"},
  "cloudflare_zone_setting.lidersea_com_tls_1_3": {"zone_id", "setting_id", "value"},
  "cloudflare_zone_setting.lidersea_com_zero_rtt": {"zone_id", "setting_id", "value"},
  "cloudflare_zone_setting.lidersea_com_ssl": {"zone_id", "setting_id", "value"},
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
  "cloudflare_zone_setting": {"zone_id", "setting_id", "value"},
}

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

# One site root, proved whole: the adopted Tunnel identity, its exact single
# public ingress plus terminal catch-all, its own proxied apex CNAME derived
# from that same Tunnel, and the five zone settings that carry the security
# target state. Nothing here reaches the other site.
site_root_exact(name) if {
  contract := site_contracts[name]
  account_id := variable_value("cloudflare_account_id")
  zone_id := variable_value(contract.zone_variable)
  valid_account_id(account_id)
  valid_account_id(zone_id)
  account_id != zone_id
  valid_contract_hash(variable_value(contract.audit_variable))

  tunnel_address := sprintf("cloudflare_zero_trust_tunnel_cloudflared.%s", [contract.slug])
  tunnel := change_after(tunnel_address)
  account_matches(tunnel)
  tunnel.name == contract.tunnel_name
  tunnel.config_src == "cloudflare"
  object.get(tunnel, "tunnel_secret", null) == null
  has_exact_reference(tunnel_address, "account_id", "var.cloudflare_account_id")

  config_address := sprintf("cloudflare_zero_trust_tunnel_cloudflared_config.%s", [contract.slug])
  edge := change_after(config_address)
  account_matches(edge)
  edge.source == "cloudflare"
  object.keys(edge.config) == {"ingress"}
  count(edge.config.ingress) == 2
  edge.config.ingress[0] == {"hostname": contract.hostname, "service": contract.origin}
  edge.config.ingress[1] == {"service": "http_status:404"}
  has_exact_reference(config_address, "account_id", "var.cloudflare_account_id")
  has_only_id_tree(config_address, "tunnel_id", tunnel_address)

  apex_address := sprintf("cloudflare_dns_record.%s_apex", [contract.slug])
  apex := change_after(apex_address)
  apex.zone_id == zone_id
  apex.name == contract.hostname
  apex.type == "CNAME"
  apex.proxied == true
  apex.ttl == 1
  regex.match(
    `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[.]cfargotunnel[.]com$`,
    apex.content,
  )
  has_exact_reference(apex_address, "zone_id", sprintf("var.%s", [contract.zone_variable]))
  has_only_id_tree(apex_address, "content", tunnel_address)

  every setting_key, setting in zone_setting_contracts {
    exact_zone_setting(contract, setting_key, setting, zone_id)
  }
}

exact_zone_setting(contract, setting_key, setting, zone_id) if {
  address := sprintf("cloudflare_zone_setting.%s_%s", [contract.slug, setting_key])
  planned := change_after(address)
  planned.zone_id == zone_id
  planned.setting_id == setting.setting_id
  planned.value == setting.value
  has_exact_reference(address, "zone_id", sprintf("var.%s", [contract.zone_variable]))
}

adoption_action(actions) if {
  actions == ["no-op"]
}

adoption_action(actions) if {
  actions == ["update"]
}

ingress_rules(change) := rules if {
  after := object.get(change.change, "after", {})
  is_object(after)
  config := object.get(after, "config", {})
  is_object(config)
  rules := object.get(config, "ingress", [])
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
  phase in adopt_only_phases
  site_root_exact(phase)
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
  phase in create_only_phases
  some change in managed_changes
  change.change.actions != ["create"]
  msg := sprintf("initial activation plans must contain create actions only: %s", [change.address])
}

deny contains msg if {
  phase in create_only_phases
  some change in managed_changes
  object.get(change.change, "before", null) != null
  msg := sprintf("initial activation plans must have no prior object: %s", [change.address])
}

# Adoption contract. The live Tunnels and apex records predate this repository:
# a site plan confirms them or moves a zone setting to its target, and anything
# that would create, delete, or replace a live object is a hard stop.
deny contains msg if {
  phase in adopt_only_phases
  some change in managed_changes
  not adoption_action(change.change.actions)
  msg := sprintf("site roots adopt live objects; only no-op or update is permitted: %s", [change.address])
}

deny contains msg if {
  phase in adopt_only_phases
  some change in managed_changes
  object.get(change.change, "before", null) == null
  msg := sprintf("site roots must never create a live object; import it first: %s", [change.address])
}

deny contains msg if {
  phase in adopt_only_phases
  some change in managed_changes
  change.type in adopted_identity_types
  change.change.actions != ["no-op"]
  msg := sprintf("adopted Tunnel and apex identity must plan as no-op: %s", [change.address])
}

# Safety invariant 3: no origin address record may ever reach a zone here.
deny contains msg if {
  some change in managed_changes
  change.type == "cloudflare_dns_record"
  object.get(object.get(change.change, "after", {}), "type", "") in forbidden_dns_record_types
  msg := sprintf("origin address records are forbidden: %s", [change.address])
}

deny contains msg if {
  some change in managed_changes
  change.type == "cloudflare_dns_record"
  contains(object.get(object.get(change.change, "after", {}), "name", ""), "*")
  msg := sprintf("wildcard DNS names are forbidden: %s", [change.address])
}

deny contains msg if {
  some change in managed_changes
  some rule in ingress_rules(change)
  contains(object.get(rule, "hostname", ""), "*")
  msg := sprintf("wildcard Tunnel hostnames are forbidden: %s", [change.address])
}

# A public site Tunnel never carries private-network reach.
deny contains msg if {
  some change in managed_changes
  after := object.get(change.change, "after", {})
  is_object(after)
  config := object.get(after, "config", {})
  is_object(config)
  "warp_routing" in object.keys(config)
  msg := sprintf("WARP or private routing is forbidden on a public Tunnel: %s", [change.address])
}

deny contains msg if {
  phase in adopt_only_phases
  some change in managed_changes
  change.type == "cloudflare_zero_trust_tunnel_cloudflared_route"
  msg := sprintf("private routes are forbidden in a public site root: %s", [change.address])
}

# Site isolation. The other site's identity token must not appear in this
# root's planned values, its ingress rules, or its configuration references.
deny contains msg if {
  contract := site_contracts[phase]
  some change in managed_changes
  some field, value in object.get(change.change, "after", {})
  is_string(value)
  contains(value, contract.foreign_marker)
  msg := sprintf("cross-site value is forbidden in %s: %s.%s", [phase, change.address, field])
}

deny contains msg if {
  contract := site_contracts[phase]
  some change in managed_changes
  some rule in ingress_rules(change)
  some field, value in rule
  is_string(value)
  contains(value, contract.foreign_marker)
  msg := sprintf("cross-site ingress value is forbidden in %s: %s.%s", [phase, change.address, field])
}

deny contains msg if {
  contract := site_contracts[phase]
  some resource in configured_managed
  some field, expression in object.get(resource, "expressions", {})
  some reference in object.get(expression, "references", [])
  contains(reference, contract.foreign_marker)
  msg := sprintf("cross-site reference is forbidden in %s: %s.%s", [phase, resource.address, field])
}

# The zone security target state, named setting by setting so a drifted value
# reports which control moved instead of one opaque contract failure.
deny contains msg if {
  contract := site_contracts[phase]
  some setting_key, setting in zone_setting_contracts
  planned := change_after(sprintf("cloudflare_zone_setting.%s_%s", [contract.slug, setting_key]))
  object.get(planned, "setting_id", "") != setting.setting_id
  msg := sprintf("zone setting %s is bound to the wrong control in %s", [setting_key, phase])
}

deny contains msg if {
  contract := site_contracts[phase]
  some setting_key, setting in zone_setting_contracts
  planned := change_after(sprintf("cloudflare_zone_setting.%s_%s", [contract.slug, setting_key]))
  object.get(planned, "value", null) != setting.value
  msg := sprintf("zone setting %s must equal %v in %s", [setting.setting_id, setting.value, phase])
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
