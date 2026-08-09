#!/usr/bin/env python3
"""Create one deterministic negative Cloudflare plan fixture for Rego tests."""

import argparse
import copy
import json
import sys
from pathlib import Path


def exactly_one(items, address):
    """Return one addressed plan object so a broken base fixture fails loudly."""

    matches = [item for item in items if item.get("address") == address]
    if len(matches) != 1:
        raise ValueError("expected exactly one fixture object at {}".format(address))
    return matches[0]


def mutate(plan, name):
    """Apply one named violation without changing unrelated plan evidence."""

    changes = plan["resource_changes"]
    configured = plan["configuration"]["root_module"]["resources"]
    change = lambda address: exactly_one(changes, address)["change"]
    resource = lambda address: exactly_one(configured, address)

    if name == "disabled-block":
        change("cloudflare_zero_trust_gateway_policy.pi_admin_block[0]")["after"]["enabled"] = False
    elif name == "widened-traffic":
        target = change("cloudflare_zero_trust_gateway_policy.pi_admin_allow[0]")["after"]
        target["traffic"] += " or net.dst.port == 443"
    elif name == "public-admin-cidr":
        change("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin[0]")["after"]["network"] = "192.0.2.10/32"
    elif name == "unknown-block-state":
        target = change("cloudflare_zero_trust_gateway_policy.pi_admin_block[0]")
        target.setdefault("after_unknown", {})["enabled"] = True
    elif name == "wrong-route-tunnel":
        target = resource("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin")
        target["expressions"]["tunnel_id"]["references"] = ["cloudflare_zero_trust_tunnel_cloudflared.pi_websites"]
    elif name == "extra-route-reference":
        target = resource("cloudflare_zero_trust_tunnel_cloudflared_route.pi_admin")
        target["expressions"]["tunnel_id"]["references"].append("cloudflare_zero_trust_tunnel_cloudflared.pi_websites")
    elif name == "wrong-identity-variable":
        target = resource("cloudflare_zero_trust_gateway_policy.pi_admin_allow")
        target["expressions"]["identity"]["references"] = ["var.zone_name"]
    elif name == "duplicate-tunnel-name":
        change("cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0]")["after"]["name"] = "pi-admin"
    elif name == "mismatched-public-hostname":
        change("cloudflare_dns_record.naranjo_online[0]")["after"]["name"] = "other.example.invalid"
    elif name == "mismatched-lidersea-hostname":
        change("cloudflare_dns_record.lidersea_com[0]")["after"]["name"] = "other.example.invalid"
    elif name == "swapped-public-ingress":
        ingress = change("cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites[0]")["after"]["config"]["ingress"]
        ingress[0], ingress[1] = ingress[1], ingress[0]
    elif name == "wrong-lidersea-origin":
        ingress = change("cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites[0]")["after"]["config"]["ingress"]
        ingress[1]["service"] = "http://naranjo-online.naranjo-online.svc.cluster.local:8080"
    elif name == "nonterminal-catchall":
        ingress = change("cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites[0]")["after"]["config"]["ingress"]
        ingress[1], ingress[2] = ingress[2], ingress[1]
    elif name == "duplicate-ingress-hostname":
        ingress = change("cloudflare_zero_trust_tunnel_cloudflared_config.pi_websites[0]")["after"]["config"]["ingress"]
        ingress[1]["hostname"] = "naranjo.online"
    elif name == "widened-filters":
        change("cloudflare_zero_trust_gateway_policy.pi_admin_allow[0]")["after"]["filters"] = ["l4", "dns"]
    elif name == "cloudflare-data-source":
        # Data sources could discover infrastructure outside the reviewed
        # inputs, so inject both the planned and configured representations.
        changes.append({
            "address": "data.cloudflare_zones.all",
            "mode": "data",
            "type": "cloudflare_zones",
            "change": {"actions": ["read"], "after": {}, "after_unknown": {}},
        })
        configured.append({
            "address": "data.cloudflare_zones.all",
            "mode": "data",
            "type": "cloudflare_zones",
            "expressions": {},
        })
    elif name == "cross-account-target":
        change("cloudflare_zero_trust_tunnel_cloudflared.pi_admin[0]")["after"]["account_id"] = (
            "4" * 32
        )
    elif name == "wrong-account-variable":
        target = resource("cloudflare_zero_trust_tunnel_cloudflared.pi_admin")
        target["expressions"]["account_id"]["references"] = [
            "var.cloudflare_naranjo_online_zone_id"
        ]
    elif name == "literal-account-target":
        target = resource("cloudflare_zero_trust_tunnel_cloudflared.pi_admin")
        target["expressions"]["account_id"] = {
            "constant_value": "11111111111111111111111111111111"
        }
    elif name == "missing-account-target":
        del change("cloudflare_zero_trust_tunnel_cloudflared.pi_admin[0]")["after"][
            "account_id"
        ]
    elif name == "unknown-account-target":
        target = change("cloudflare_zero_trust_tunnel_cloudflared.pi_admin[0]")
        target["after"]["account_id"] = None
        target.setdefault("after_unknown", {})["account_id"] = True
    elif name == "wrong-zone-variable":
        target = resource("cloudflare_dns_record.naranjo_online")
        target["expressions"]["zone_id"]["references"] = ["var.cloudflare_account_id"]
    elif name == "wrong-lidersea-zone-variable":
        target = resource("cloudflare_dns_record.lidersea_com")
        target["expressions"]["zone_id"]["references"] = [
            "var.cloudflare_naranjo_online_zone_id"
        ]
    elif name == "swapped-zone-variables":
        naranjo = resource("cloudflare_dns_record.naranjo_online")["expressions"]["zone_id"]
        lidersea = resource("cloudflare_dns_record.lidersea_com")["expressions"]["zone_id"]
        naranjo["references"], lidersea["references"] = (
            lidersea["references"],
            naranjo["references"],
        )
    elif name == "literal-zone-target":
        target = resource("cloudflare_dns_record.lidersea_com")
        target["expressions"]["zone_id"] = {
            "constant_value": "33333333333333333333333333333333"
        }
    elif name == "missing-zone-target":
        del change("cloudflare_dns_record.lidersea_com[0]")["after"]["zone_id"]
    elif name == "unknown-zone-target":
        target = change("cloudflare_dns_record.lidersea_com[0]")
        target["after"]["zone_id"] = None
        target.setdefault("after_unknown", {})["zone_id"] = True
    elif name == "duplicate-zone-target":
        change("cloudflare_dns_record.lidersea_com[0]")["after"]["zone_id"] = (
            "22222222222222222222222222222222"
        )
    elif name == "malformed-zone-target":
        change("cloudflare_dns_record.lidersea_com[0]")["after"]["zone_id"] = "not-a-zone-id"
    elif name == "zone-equals-account-target":
        change("cloudflare_dns_record.lidersea_com[0]")["after"]["zone_id"] = (
            "11111111111111111111111111111111"
        )
    elif name == "wrong-lidersea-cname-tunnel":
        target = resource("cloudflare_dns_record.lidersea_com")
        target["expressions"]["content"]["references"] = [
            "cloudflare_zero_trust_tunnel_cloudflared.pi_admin"
        ]
    elif name == "wrong-lidersea-cname-attribute":
        target = resource("cloudflare_dns_record.lidersea_com")
        target["expressions"]["content"]["references"] = [
            "cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0].name",
            "cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0]",
            "cloudflare_zero_trust_tunnel_cloudflared.pi_websites",
        ]
    elif name == "missing-dns-record":
        changes.remove(exactly_one(changes, "cloudflare_dns_record.lidersea_com[0]"))
        configured.remove(exactly_one(configured, "cloudflare_dns_record.lidersea_com"))
    elif name == "duplicate-dns-record":
        changes.append(
            copy.deepcopy(
                exactly_one(changes, "cloudflare_dns_record.lidersea_com[0]")
            )
        )
        configured.append(
            copy.deepcopy(resource("cloudflare_dns_record.lidersea_com"))
        )
    elif name == "extra-dns-record":
        extra_config = copy.deepcopy(resource("cloudflare_dns_record.lidersea_com"))
        extra_config["address"] = "cloudflare_dns_record.forbidden_extra"
        configured.append(extra_config)
        extra_change = copy.deepcopy(
            exactly_one(changes, "cloudflare_dns_record.lidersea_com[0]")
        )
        extra_change["address"] = "cloudflare_dns_record.forbidden_extra[0]"
        changes.append(extra_change)
    elif name == "extra-public-tunnel":
        extra_config = copy.deepcopy(
            resource("cloudflare_zero_trust_tunnel_cloudflared.pi_websites")
        )
        extra_config["address"] = "cloudflare_zero_trust_tunnel_cloudflared.lidersea"
        configured.append(extra_config)
        extra_change = copy.deepcopy(
            exactly_one(changes, "cloudflare_zero_trust_tunnel_cloudflared.pi_websites[0]")
        )
        extra_change["address"] = "cloudflare_zero_trust_tunnel_cloudflared.lidersea[0]"
        extra_change["change"]["after"]["name"] = "lidersea"
        changes.append(extra_change)
    else:
        raise ValueError("unknown mutation {}".format(name))


def main(argv=None):
    """Parse, mutate, and serialize a stable negative fixture for shell tests."""

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
        print("FAIL unable to create Cloudflare fixture mutation: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
