package main

import rego.v1

# This policy is the machine-enforced edge of the zero-spend contract. It
# deliberately accepts one small, named topology so a syntactically valid plan
# cannot quietly introduce a paid product, a wider route, or a second target.
allowed_types := {
  "cloudflare_dns_record",
  "cloudflare_zero_trust_gateway_policy",
  "cloudflare_zero_trust_tunnel_cloudflared",
  "cloudflare_zero_trust_tunnel_cloudflared_config",
  "cloudflare_zero_trust_tunnel_cloudflared_route",
}

# Account- and zone-scoped resources are kept separate because their target IDs
# have different meanings. The plan gate hashes the account and both labelled
# zone IDs without printing them; operators compare that hash with the read-only
# audit before approving a plan.
account_scoped_types := {
  "cloudflare_zero_trust_gateway_policy",
  "cloudflare_zero_trust_tunnel_cloudflared",
  "cloudflare_zero_trust_tunnel_cloudflared_config",
  "cloudflare_zero_trust_tunnel_cloudflared_route",
}

account_scoped_configuration_addresses := {
  "cloudflare_zero_trust_tunnel_cloudflared.pi_admin",
  "cloudflare_zero_trust_tunnel_cloudflared.pi_websites",
  "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin",
  "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites",
  "cloudflare_zero_trust_gateway_policy.pi_admin_allow",
  "cloudflare_zero_trust_gateway_policy.pi_admin_block",
}

zone_scoped_configuration_targets := {
  "cloudflare_dns_record.naranjo_online": "var.cloudflare_naranjo_online_zone_id",
  "cloudflare_dns_record.lidersea_com":    "var.cloudflare_lidersea_com_zone_id",
}

expected_configuration_addresses := {
  "cloudflare_zero_trust_tunnel_cloudflared.pi_admin",
  "cloudflare_zero_trust_tunnel_cloudflared.pi_websites",
  "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin",
  "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites",
  "cloudflare_dns_record.naranjo_online",
  "cloudflare_dns_record.lidersea_com",
  "cloudflare_zero_trust_gateway_policy.pi_admin_allow",
  "cloudflare_zero_trust_gateway_policy.pi_admin_block",
}

canonical_naranjo_online_hostname := "naranjo.online"
canonical_naranjo_online_origin := "http://naranjo-online.naranjo-online.svc.cluster.local:8080"
canonical_lidersea_com_hostname := "lidersea.com"
canonical_lidersea_com_origin := "http://lidersea-com.lidersea-com.svc.cluster.local:8080"

expected_addresses := {
  "cloudflare_zero_trust_tunnel_cloudflared.pi_admin[0]",
  "cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0]",
  "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin[0]",
  "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites[0]",
  "cloudflare_dns_record.naranjo_online[0]",
  "cloudflare_dns_record.lidersea_com[0]",
  "cloudflare_zero_trust_gateway_policy.pi_admin_allow[0]",
  "cloudflare_zero_trust_gateway_policy.pi_admin_block[0]",
}

critical_fields := {
  "cloudflare_zero_trust_tunnel_cloudflared": {"account_id", "name", "config_src"},
  "cloudflare_zero_trust_tunnel_cloudflared_route": {"account_id", "network", "comment"},
  "cloudflare_zero_trust_tunnel_cloudflared_config": {"account_id", "config", "source"},
  "cloudflare_dns_record": {"zone_id", "name", "type", "proxied", "ttl"},
  "cloudflare_zero_trust_gateway_policy": {
    "account_id", "name", "action", "enabled", "filters", "precedence", "traffic",
    "identity", "device_posture",
  },
}

managed_changes := [change |
  some change in object.get(input, "resource_changes", [])
  object.get(change, "mode", "managed") == "managed"
]

actual_addresses := {change.address | some change in managed_changes}

configuration_resources := object.get(
  object.get(object.get(input, "configuration", {}), "root_module", {}),
  "resources",
  [],
)

cloudflare_configuration_resources := [resource |
  some resource in configuration_resources
  object.get(resource, "mode", "managed") == "managed"
  startswith(object.get(resource, "type", split(object.get(resource, "address", ""), ".")[0]), "cloudflare_")
]

actual_configuration_addresses := {
  resource.address | some resource in cloudflare_configuration_resources
}

cloudflare_data_changes := [change |
  some change in object.get(input, "resource_changes", [])
  object.get(change, "mode", "managed") == "data"
  startswith(object.get(change, "type", ""), "cloudflare_")
]

cloudflare_data_configuration := [resource |
  some resource in configuration_resources
  object.get(resource, "mode", "managed") == "data"
  startswith(object.get(resource, "type", ""), "cloudflare_")
]

has_exact_reference(address, field, expected) if {
  some resource in configuration_resources
  resource.address == address
  expressions := object.get(resource, "expressions", {})
  references := object.get(object.get(expressions, field, {}), "references", [])
  count(references) == 1
  references[0] == expected
}

# OpenTofu expands a resource traversal into each significant step in plan
# JSON. Accept only the base, index-zero, and exact `.id` traversal while
# rejecting another attribute, instance, resource, variable, or literal target.
reference_within_tree(reference, expected) if {
  reference == expected
}

reference_within_tree(reference, expected) if {
  reference == sprintf("%s[0]", [expected])
}

reference_within_tree(reference, expected) if {
  reference == sprintf("%s[0].id", [expected])
}

has_only_reference_tree(address, field, expected) if {
  some resource in configuration_resources
  resource.address == address
  expressions := object.get(resource, "expressions", {})
  references := object.get(object.get(expressions, field, {}), "references", [])
  expected in references
  sprintf("%s[0].id", [expected]) in references
  every reference in references {
    reference_within_tree(reference, expected)
  }
}

# Cloudflare account and zone identifiers are opaque lowercase hex strings. A
# target that is missing, unknown, or malformed cannot be tied back to an audit.
valid_target_id(identifier) if {
  regex.match(`^[0-9a-f]{32}$`, identifier)
}

account_target_ids := {
  object.get(change.change.after, "account_id", "") |
  some change in managed_changes
  change.type in account_scoped_types
}

zone_target_ids := {
  object.get(change.change.after, "zone_id", "") |
  some change in managed_changes
  change.type == "cloudflare_dns_record"
}

private_ipv4_32(network) if {
  regex.match(`^[0-9.]+/32$`, network)
  net.cidr_contains("10.0.0.0/8", network)
}

exact_dns(dns) if {
  dns.type == "CNAME"
  dns.proxied == true
  dns.ttl == 1
}

exact_allow_metadata(policy) if {
  policy.name == "pi-admin-allow"
  policy.action == "allow"
  policy.enabled == true
}

exact_block_metadata(policy) if {
  policy.name == "pi-admin-block"
  policy.action == "block"
  policy.enabled == true
}

private_ipv4_32(network) if {
  regex.match(`^[0-9.]+/32$`, network)
  net.cidr_contains("172.16.0.0/12", network)
}

private_ipv4_32(network) if {
  regex.match(`^[0-9.]+/32$`, network)
  net.cidr_contains("192.168.0.0/16", network)
}

deny contains msg if {
  some change in cloudflare_data_changes
  msg := sprintf("Cloudflare data sources are forbidden: %s", [change.address])
}

deny contains msg if {
  some resource in cloudflare_data_configuration
  msg := sprintf("Cloudflare data sources are forbidden in configuration: %s", [resource.address])
}

deny contains msg if {
  some change in managed_changes
  not change.type in allowed_types
  msg := sprintf("resource type is not allowed: %s", [change.type])
}

deny contains msg if {
  some change in managed_changes
  "delete" in change.change.actions
  msg := sprintf("destruction is blocked: %s", [change.address])
}

deny contains msg if {
  count(managed_changes) != 8
  msg := sprintf("the plan must contain exactly eight managed instances, found %d", [count(managed_changes)])
}

deny contains msg if {
  actual_addresses != expected_addresses
  msg := sprintf("managed addresses must exactly match the eight-resource contract: %v", [actual_addresses])
}

deny contains msg if {
  count(cloudflare_configuration_resources) != 8
  msg := sprintf("configuration must contain exactly eight managed Cloudflare resources, found %d", [count(cloudflare_configuration_resources)])
}

deny contains msg if {
  actual_configuration_addresses != expected_configuration_addresses
  msg := "Cloudflare configuration must exactly declare the eight-resource contract"
}

deny contains msg if {
  some address in account_scoped_configuration_addresses
  not has_exact_reference(address, "account_id", "var.cloudflare_account_id")
  msg := sprintf("account-scoped resource must reference only var.cloudflare_account_id: %s", [address])
}

deny contains msg if {
  some address, expected_reference in zone_scoped_configuration_targets
  not has_exact_reference(address, "zone_id", expected_reference)
  msg := sprintf("zone-scoped resource has a missing, literal, or cross-wired zone variable: %s", [address])
}

deny contains msg if {
  count(account_target_ids) != 1
  msg := "all account-scoped resources must resolve to one exact account ID"
}

deny contains msg if {
  some identifier in account_target_ids
  not valid_target_id(identifier)
  msg := "every account-scoped resource must expose a known 32-character account ID"
}

deny contains msg if {
  count(zone_target_ids) != 2
  msg := "the two DNS records must resolve to two distinct exact zone IDs"
}

deny contains msg if {
  some identifier in zone_target_ids
  not valid_target_id(identifier)
  msg := "every zone-scoped resource must expose a known 32-character zone ID"
}

deny contains msg if {
  count(zone_target_ids & account_target_ids) != 0
  msg := "a zone target must not equal the account target"
}

deny contains msg if {
  some change in managed_changes
  some field in object.get(critical_fields, change.type, {})
  object.get(object.get(change.change, "after_unknown", {}), field, false) != false
  msg := sprintf("critical field is unknown for %s: %s", [change.address, field])
}

tunnels := [change |
  some change in managed_changes
  change.type == "cloudflare_zero_trust_tunnel_cloudflared"
]

deny contains msg if {
  some change in tunnels
  expected_name := {
    "cloudflare_zero_trust_tunnel_cloudflared.pi_admin[0]": "pi-admin",
    "cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0]": "pi-websites",
  }[change.address]
  object.get(change.change.after, "name", "") != expected_name
  msg := sprintf("tunnel name/address mismatch: %s", [change.address])
}

deny contains msg if {
  some change in tunnels
  object.get(change.change.after, "config_src", "") != "cloudflare"
  msg := sprintf("tunnel must be remotely managed: %s", [change.address])
}

deny contains msg if {
  some change in tunnels
  object.get(change.change.after, "tunnel_secret", null) != null
  msg := sprintf("tunnel secret must not enter state: %s", [change.address])
}

routes := [change |
  some change in managed_changes
  change.address == "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin[0]"
]

deny contains msg if {
  route := routes[0]
  not private_ipv4_32(route.change.after.network)
  msg := "pi-admin route must be one RFC1918 IPv4 /32"
}

deny contains msg if {
  routes[0].change.after.comment != "Pi host only; no LAN subnet"
  msg := "pi-admin route comment must preserve the exact /32-only intent"
}

deny contains msg if {
  not has_only_reference_tree(
    "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin",
    "tunnel_id",
    "cloudflare_zero_trust_tunnel_cloudflared.pi_admin",
  )
  msg := "the private route must reference only the pi-admin tunnel"
}

configs := [change |
  some change in managed_changes
  change.address == "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites[0]"
]

deny contains msg if {
  not has_only_reference_tree(
    "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites",
    "tunnel_id",
    "cloudflare_zero_trust_tunnel_cloudflared.pi_websites",
  )
  msg := "the public config must reference only the pi-websites tunnel"
}

deny contains msg if {
  config := configs[0]
  config.change.after.source != "cloudflare"
  msg := "pi-websites config must be remotely managed"
}

deny contains msg if {
  config := configs[0]
  ingress := config.change.after.config.ingress
  count(ingress) != 3
  msg := "pi-websites must have two ordered hostname routes and one catch-all"
}

deny contains msg if {
  config := configs[0]
  ingress := config.change.after.config.ingress
  object.get(ingress[0], "hostname", "") != canonical_naranjo_online_hostname
  msg := "the public ingress hostname must be exactly naranjo.online"
}

deny contains msg if {
  config := configs[0]
  ingress := config.change.after.config.ingress
  ingress[0].service != canonical_naranjo_online_origin
  msg := "public hostname origin must be the naranjo-online ClusterIP Service"
}

deny contains msg if {
  config := configs[0]
  ingress := config.change.after.config.ingress
  object.get(ingress[1], "hostname", "") != canonical_lidersea_com_hostname
  msg := "the second public ingress hostname must be exactly lidersea.com"
}

deny contains msg if {
  config := configs[0]
  ingress := config.change.after.config.ingress
  ingress[1].service != canonical_lidersea_com_origin
  msg := "lidersea.com origin must be the lidersea-com ClusterIP Service"
}

deny contains msg if {
  config := configs[0]
  ingress := config.change.after.config.ingress
  ingress[2].service != "http_status:404"
  msg := "the final tunnel ingress rule must be http_status:404"
}

deny contains msg if {
  config := configs[0]
  ingress := config.change.after.config.ingress
  object.get(ingress[2], "hostname", null) != null
  msg := "the final tunnel ingress rule must be an unqualified catch-all"
}

dns_records := [change |
  some change in managed_changes
  change.type == "cloudflare_dns_record"
]

deny contains msg if {
  some record in dns_records
  dns := record.change.after
  not exact_dns(dns)
  msg := sprintf("public DNS must be a proxied automatic-TTL CNAME: %s", [record.address])
}

naranjo_online_dns_records := [change |
  some change in managed_changes
  change.address == "cloudflare_dns_record.naranjo_online[0]"
]

lidersea_com_dns_records := [change |
  some change in managed_changes
  change.address == "cloudflare_dns_record.lidersea_com[0]"
]

deny contains msg if {
  dns := naranjo_online_dns_records[0].change.after
  ingress := configs[0].change.after.config.ingress
  dns.name != ingress[0].hostname
  msg := "naranjo.online DNS and tunnel ingress hostnames must match exactly"
}

deny contains msg if {
  dns := naranjo_online_dns_records[0].change.after
  dns.name != canonical_naranjo_online_hostname
  msg := "public DNS must be exactly naranjo.online"
}

deny contains msg if {
  dns := lidersea_com_dns_records[0].change.after
  ingress := configs[0].change.after.config.ingress
  dns.name != ingress[1].hostname
  msg := "lidersea.com DNS and tunnel ingress hostnames must match exactly"
}

deny contains msg if {
  dns := lidersea_com_dns_records[0].change.after
  dns.name != canonical_lidersea_com_hostname
  msg := "public DNS must be exactly lidersea.com"
}

deny contains msg if {
  some address in object.keys(zone_scoped_configuration_targets)
  not has_only_reference_tree(
    address,
    "content",
    "cloudflare_zero_trust_tunnel_cloudflared.pi_websites",
  )
  msg := sprintf("public CNAME must reference only the one pi-websites tunnel: %s", [address])
}

deny contains msg if {
  not has_exact_reference(
    "cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin",
    "network",
    "var.pi_admin_cidr",
  )
  msg := "the private route network must reference only var.pi_admin_cidr"
}

deny contains msg if {
  not has_exact_reference(
    "cloudflare_zero_trust_gateway_policy.pi_admin_allow",
    "identity",
    "var.admin_email",
  )
  msg := "the allow identity must reference only var.admin_email"
}

deny contains msg if {
  not has_exact_reference(
    "cloudflare_zero_trust_gateway_policy.pi_admin_allow",
    "device_posture",
    "var.admin_device_posture_check_id",
  )
  msg := "the allow posture must reference only var.admin_device_posture_check_id"
}

deny contains msg if {
  not has_exact_reference(
    "cloudflare_zero_trust_gateway_policy.pi_admin_allow",
    "traffic",
    "var.pi_admin_cidr",
  )
  msg := "the allow traffic must reference only var.pi_admin_cidr"
}

deny contains msg if {
  not has_exact_reference(
    "cloudflare_zero_trust_gateway_policy.pi_admin_block",
    "traffic",
    "var.pi_admin_cidr",
  )
  msg := "the block traffic must reference only var.pi_admin_cidr"
}

gateway_policies := [change |
  some change in managed_changes
  change.type == "cloudflare_zero_trust_gateway_policy"
]

allow_policies := [change.change.after |
  some change in gateway_policies
  change.address == "cloudflare_zero_trust_gateway_policy.pi_admin_allow[0]"
]

block_policies := [change.change.after |
  some change in gateway_policies
  change.address == "cloudflare_zero_trust_gateway_policy.pi_admin_block[0]"
]

deny contains msg if {
  allow := allow_policies[0]
  not exact_allow_metadata(allow)
  msg := "pi-admin-allow must be enabled and use the exact name/action"
}

deny contains msg if {
  block := block_policies[0]
  not exact_block_metadata(block)
  msg := "pi-admin-block must be enabled and use the exact name/action"
}

deny contains msg if {
  some policy in array.concat(allow_policies, block_policies)
  policy.filters != ["l4"]
  msg := "both Gateway policies must use only the l4 filter"
}

deny contains msg if {
  network := routes[0].change.after.network
  allow := allow_policies[0]
  allow.traffic != sprintf(`net.dst.ip in {%s} and net.protocol == "tcp" and net.dst.port in {22 6443}`, [network])
  msg := "pi-admin-allow traffic must exactly match the /32 and TCP ports 22/6443"
}

deny contains msg if {
  network := routes[0].change.after.network
  block := block_policies[0]
  block.traffic != sprintf("net.dst.ip in {%s}", [network])
  msg := "pi-admin-block must exactly match every Gateway flow to the /32"
}

deny contains msg if {
  allow := allow_policies[0]
  not regex.match(`^identity[.]email == "[^"[:space:]]+@[^"[:space:]]+[.][^"[:space:]]+"$`, allow.identity)
  msg := "pi-admin-allow identity must contain exactly one email equality"
}

deny contains msg if {
  allow := allow_policies[0]
  not regex.match(`^any[(]device_posture[.]checks[.]passed\[\*\] in \{"[A-Za-z0-9_-]+"\}[)]$`, allow.device_posture)
  msg := "pi-admin-allow posture must contain exactly one required check"
}

deny contains msg if {
  allow := allow_policies[0]
  block := block_policies[0]
  allow.precedence >= block.precedence
  msg := "pi-admin exact allow must evaluate before the final block"
}
