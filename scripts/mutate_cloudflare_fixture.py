#!/usr/bin/env python3
"""Create one deterministic negative Cloudflare phase-plan fixture."""

import argparse
import copy
import json
import sys
from pathlib import Path


APPROVAL_VARIABLE = {
    "admin-tunnel": "approve_admin_tunnel_phase",
    "admin-policies": "approve_admin_policies_phase",
    "admin-route": "approve_admin_route_phase",
    "admin-api": "enable_kubernetes_api_access",
    "public-edge": "approve_public_edge_phase",
    "public-dns-naranjo": "enable_public_dns_naranjo_activation",
    "public-dns-lidersea": "enable_public_dns_lidersea_activation",
}


def exactly_one(items, address):
    """Return one addressed object so a broken base fixture fails loudly."""

    matches = [item for item in items if item.get("address") == address]
    if len(matches) != 1:
        raise ValueError("expected exactly one fixture object at {}".format(address))
    return matches[0]


def mutate(plan, name):
    """Apply one named violation without changing unrelated evidence."""

    phase = plan["codex_contract"]["phase"]
    changes = plan["resource_changes"]
    configured = plan["configuration"]["root_module"]["resources"]
    variables = plan["variables"]

    def after(address):
        return exactly_one(changes, address)["change"]["after"]

    def config(address):
        return exactly_one(configured, address)

    if name == "false-approval":
        variables[APPROVAL_VARIABLE[phase]]["value"] = False
    elif name == "delete-resource":
        changes[0]["change"]["actions"] = ["delete"]
    elif name == "cloudflare-data-source":
        changes.append(
            {
                "address": "data.cloudflare_zones.all",
                "mode": "data",
                "type": "cloudflare_zones",
                "change": {"actions": ["read"], "after": {}, "after_unknown": {}},
            }
        )
        configured.append(
            {
                "address": "data.cloudflare_zones.all",
                "mode": "data",
                "type": "cloudflare_zones",
                "expressions": {},
            }
        )
    elif name == "extra-resource":
        extra_change = copy.deepcopy(changes[0])
        extra_change["address"] += "_forbidden"
        changes.append(extra_change)
        extra_config = copy.deepcopy(configured[0])
        extra_config["address"] += "_forbidden"
        configured.append(extra_config)
    elif name == "extra-configured-field":
        configured[0]["expressions"]["unreviewed_argument"] = {}
    elif name == "wrong-account-variable":
        config(configured[0]["address"])["expressions"]["account_id"] = {
            "references": ["var.unreviewed_account_id"]
        }
    elif name == "unknown-critical":
        target = changes[0]["change"]
        field = "name" if "name" in target["after"] else next(iter(target["after"]))
        target.setdefault("after_unknown", {})[field] = True
    elif name == "disabled-block":
        after("cloudflare_zero_trust_gateway_policy.pi_admin_block")["enabled"] = False
    elif name == "widened-ssh-traffic":
        after("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow")["traffic"] += (
            " or net.dst.port == 443"
        )
    elif name == "api-in-ssh-phase":
        target = after("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow")
        target["traffic"] = target["traffic"].replace("{22}", "{22 6443}")
    elif name == "widened-filters":
        after("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow")["filters"] = [
            "l4",
            "dns",
        ]
    elif name == "wrong-identity-variable":
        config("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow")[
            "expressions"
        ]["identity"] = {"references": ["var.unreviewed_identity"]}
    elif name == "missing-block":
        changes.remove(
            exactly_one(changes, "cloudflare_zero_trust_gateway_policy.pi_admin_block")
        )
        configured.remove(
            exactly_one(
                configured, "cloudflare_zero_trust_gateway_policy.pi_admin_block"
            )
        )
    elif name == "swapped-precedence":
        after("cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow")[
            "precedence"
        ] = 1100
    elif name == "no-session-enforcement":
        address = {
            "admin-policies": "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow",
            "admin-api": "cloudflare_zero_trust_gateway_policy.pi_admin_api_allow",
        }[phase]
        after(address)["rule_settings"]["check_session"]["enforce"] = False
    elif name == "extra-session-setting":
        address = {
            "admin-policies": "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow",
            "admin-api": "cloudflare_zero_trust_gateway_policy.pi_admin_api_allow",
        }[phase]
        after(address)["rule_settings"]["unreviewed"] = {"enabled": True}
    elif name == "widened-route":
        target = after("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin")
        target["network"] = target["network"].rsplit(".", 1)[0] + ".0/24"
    elif name == "public-route":
        after("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin")[
            "network"
        ] = "192.0.2.10/32"
    elif name == "wrong-route-tunnel-variable":
        config("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin")[
            "expressions"
        ]["tunnel_id"] = {"references": ["var.pi_websites_tunnel_id"]}
    elif name == "missing-policies-contract":
        variables["verified_admin_policies_contract_sha256"]["value"] = ""
    elif name == "zero-policies-contract":
        variables["verified_admin_policies_contract_sha256"]["value"] = "0" * 64
    elif name == "wrong-route-comment":
        after("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin")[
            "comment"
        ] = "Pi LAN"
    elif name == "missing-tunnel-contract":
        variables["verified_admin_tunnel_contract_sha256"]["value"] = ""
    elif name == "zero-tunnel-contract":
        variables["verified_admin_tunnel_contract_sha256"]["value"] = "0" * 64
    elif name == "missing-posture-contract":
        variables["verified_admin_posture_contract_sha256"]["value"] = ""
    elif name == "zero-posture-contract":
        variables["verified_admin_posture_contract_sha256"]["value"] = "0" * 64
    elif name == "missing-policy-inputs-contract":
        variables["verified_admin_policy_inputs_contract_sha256"]["value"] = ""
    elif name == "zero-policy-inputs-contract":
        variables["verified_admin_policy_inputs_contract_sha256"]["value"] = "0" * 64
    elif name == "identity-scoped-block":
        target = after("cloudflare_zero_trust_gateway_policy.pi_admin_block")
        target["identity"] = 'identity.email == "admin@example.invalid"'
        target["device_posture"] = (
            'any(device_posture.checks.passed[*] in '
            '{"00000000-0000-0000-0000-000000000000"})'
        )
        target["rule_settings"] = {
            "check_session": {"enforce": True, "duration": "300s"}
        }
    elif name == "expiring-block":
        after("cloudflare_zero_trust_gateway_policy.pi_admin_block")[
            "expiration"
        ] = "2026-08-09T15:00:00Z"
    elif name == "opaque-posture-id":
        variables["admin_device_posture_check_id"]["value"] = "opaque_posture"
    elif name == "wrong-api-port":
        target = after("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow")
        target["traffic"] = target["traffic"].replace("{6443}", "{443}")
    elif name == "missing-route-contract":
        variables["verified_admin_route_contract_sha256"]["value"] = ""
    elif name == "zero-route-contract":
        variables["verified_admin_route_contract_sha256"]["value"] = "0" * 64
    elif name == "missing-api-inputs-contract":
        variables["verified_admin_api_inputs_contract_sha256"]["value"] = ""
    elif name == "zero-api-inputs-contract":
        variables["verified_admin_api_inputs_contract_sha256"]["value"] = "0" * 64
    elif name == "api-after-block":
        after("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow")[
            "precedence"
        ] = 1100
    elif name == "api-precedence-offset":
        after("cloudflare_zero_trust_gateway_policy.pi_admin_api_allow")[
            "precedence"
        ] += 1
    elif name == "swapped-public-ingress":
        ingress = after(
            "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites"
        )["config"]["ingress"]
        ingress[0], ingress[1] = ingress[1], ingress[0]
    elif name == "wrong-lidersea-origin":
        after("cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites")[
            "config"
        ]["ingress"][1]["service"] = "http://unreviewed.invalid:8080"
    elif name == "nonterminal-catchall":
        ingress = after(
            "cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites"
        )["config"]["ingress"]
        ingress[1], ingress[2] = ingress[2], ingress[1]
    elif name == "duplicate-ingress-hostname":
        after("cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites")[
            "config"
        ]["ingress"][1]["hostname"] = "naranjo.online"
    elif name == "extra-public-tunnel":
        extra_change = copy.deepcopy(
            exactly_one(changes, "cloudflare_zero_trust_tunnel_cloudflared.pi_websites")
        )
        extra_change["address"] = "cloudflare_zero_trust_tunnel_cloudflared.unreviewed"
        extra_change["change"]["after"]["name"] = "unreviewed"
        changes.append(extra_change)
        extra_config = copy.deepcopy(
            exactly_one(
                configured, "cloudflare_zero_trust_tunnel_cloudflared.pi_websites"
            )
        )
        extra_config["address"] = (
            "cloudflare_zero_trust_tunnel_cloudflared.unreviewed"
        )
        configured.append(extra_config)
    elif name == "public-warp-routing":
        after("cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites")[
            "config"
        ]["warp_routing"] = {"enabled": True}
    elif name == "external-data-source":
        changes.append(
            {
                "address": "data.external.exfil",
                "mode": "data",
                "type": "external",
                "change": {"actions": ["read"], "after": {}, "after_unknown": {}},
            }
        )
        configured.append(
            {
                "address": "data.external.exfil",
                "mode": "data",
                "type": "external",
                "expressions": {},
            }
        )
    elif name == "local-exec-provisioner":
        configured[0]["provisioners"] = [
            {"type": "local-exec", "expressions": {"command": {}}}
        ]
    elif name == "module-call":
        plan["configuration"]["root_module"]["module_calls"] = {
            "unreviewed": {"source": "./unreviewed"}
        }
    elif name == "provider-override":
        plan["configuration"]["provider_config"]["cloudflare"]["expressions"] = {
            "api_token": {"constant_value": "unreviewed"}
        }
    elif name == "missing-provider-config":
        plan["configuration"].pop("provider_config")
    elif name == "stale-update":
        changes[0]["change"]["actions"] = ["update"]
        changes[0]["change"]["before"] = {"id": "preexisting"}
    elif name == "unexpected-mode":
        changes.append(
            {
                "address": "ephemeral.unreviewed",
                "mode": "ephemeral",
                "type": "ephemeral",
                "change": {"actions": ["open"], "after": {}, "after_unknown": {}},
            }
        )
        configured.append(
            {
                "address": "ephemeral.unreviewed",
                "mode": "ephemeral",
                "type": "ephemeral",
                "expressions": {},
            }
        )
    elif name == "dns-too-early":
        changes.append(
            {
                "address": "cloudflare_dns_record.too_early",
                "mode": "managed",
                "type": "cloudflare_dns_record",
                "change": {"actions": ["create"], "after": {}, "after_unknown": {}},
            }
        )
        configured.append(
            {
                "address": "cloudflare_dns_record.too_early",
                "mode": "managed",
                "type": "cloudflare_dns_record",
                "expressions": {},
            }
        )
    elif name == "wrong-public-hostname":
        address = {
            "public-dns-naranjo": "cloudflare_dns_record.naranjo_online",
            "public-dns-lidersea": "cloudflare_dns_record.lidersea_com",
        }[phase]
        after(address)["name"] = "other.invalid"
    elif name == "wrong-zone-variable":
        address = changes[0]["address"]
        config(address)["expressions"]["zone_id"] = {
            "references": ["var.cloudflare_account_id"]
        }
    elif name == "wrong-cname-tunnel-variable":
        config(changes[0]["address"])["expressions"]["content"] = {
            "references": ["var.pi_admin_tunnel_id"]
        }
    elif name == "unproxied-dns":
        after(changes[0]["address"])["proxied"] = False
    elif name == "a-record":
        after(changes[0]["address"])["type"] = "A"
    elif name == "account-as-zone-target":
        after(changes[0]["address"])["zone_id"] = variables[
            "cloudflare_account_id"
        ]["value"]
    elif name == "missing-edge-contract":
        variables["verified_public_edge_contract_sha256"]["value"] = ""
    elif name == "zero-edge-contract":
        variables["verified_public_edge_contract_sha256"]["value"] = "0" * 64
    else:
        raise ValueError("unknown mutation {} for {}".format(name, phase))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mutation")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        plan = json.loads(args.source.read_text(encoding="utf-8"))
        mutate(plan, args.mutation)
        args.output.write_text(json.dumps(plan, sort_keys=True) + "\n", encoding="utf-8")
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(
            "FAIL unable to create Cloudflare fixture mutation: {}".format(error),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
