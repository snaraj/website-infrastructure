#!/usr/bin/env python3
"""Create one deterministic negative Cloudflare phase-plan fixture."""

import argparse
import copy
import json
import sys
from pathlib import Path


APPROVAL_VARIABLE = {
    "admin-certificate": "approve_admin_certificate_phase",
    "admin-enrollment-policy": "approve_admin_enrollment_policy_phase",
    "admin-enrollment-app": "approve_admin_enrollment_app_phase",
    "admin-device": "approve_admin_device_phase",
    "admin-tunnel": "approve_admin_tunnel_phase",
    "admin-policies": "approve_admin_policies_phase",
    "admin-route": "approve_admin_route_phase",
    "site-naranjo-online": "approve_site_naranjo_online_phase",
    "site-lidersea-com": "approve_site_lidersea_com_phase",
}

# Per-site identity for the two adoption roots. ``foreign_*`` values are the
# other site's identity: every mutation built from them proves the policy
# refuses to let one site's root reach the other site's objects.
SITE_CONTEXT = {
    "site-naranjo-online": {
        "slug": "naranjo_online",
        "hostname": "naranjo.online",
        "zone_variable": "cloudflare_naranjo_online_zone_id",
        "audit_variable": "verified_naranjo_online_adoption_audit_sha256",
        "foreign_slug": "lidersea_com",
        "foreign_hostname": "lidersea.com",
        "foreign_origin": (
            "http://lidersea-com.lidersea-com.svc.cluster.local:8080"
        ),
        "foreign_variable": "var.cloudflare_lidersea_com_zone_id",
    },
    "site-lidersea-com": {
        "slug": "lidersea_com",
        "hostname": "lidersea.com",
        "zone_variable": "cloudflare_lidersea_com_zone_id",
        "audit_variable": "verified_lidersea_com_adoption_audit_sha256",
        "foreign_slug": "naranjo_online",
        "foreign_hostname": "naranjo.online",
        "foreign_origin": (
            "http://naranjo-online.naranjo-online.svc.cluster.local:8080"
        ),
        "foreign_variable": "var.cloudflare_naranjo_online_zone_id",
    },
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

    def site():
        """Return this phase's site identity, or fail closed if it has none.

        Only the two website roots carry a site identity. Asking an
        administrative phase for one is a broken call site: it must raise, so
        the driver reports a failed mutation rather than silently emitting an
        unmutated plan that the policy would then correctly accept — a
        surviving mutant dressed up as a pass.
        """

        identity = SITE_CONTEXT.get(phase)
        if identity is None:
            raise ValueError("phase {} is not a website root".format(phase))
        return identity

    def dns_address():
        return "cloudflare_dns_record.{}_apex".format(site()["slug"])

    def tunnel_address():
        return "cloudflare_zero_trust_tunnel_cloudflared.{}".format(site()["slug"])

    def tunnel_config_address():
        return "cloudflare_zero_trust_tunnel_cloudflared_config.{}".format(
            site()["slug"]
        )

    def ingress():
        return after(tunnel_config_address())["config"]["ingress"]

    def zone_setting(key):
        return "cloudflare_zone_setting.{}_{}".format(site()["slug"], key)

    def foreign_tunnel_identifier():
        """Return an identifier this root does not own.

        Derived from the plan's own identifier rather than written down: the
        repository privacy gate allows exactly one UUID literal in tracked
        text, and a forged target must never become the second one.
        """

        own = after(tunnel_address())["id"]
        return own[:-1] + ("1" if own[-1] != "1" else "2")

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
    elif name == "certificate-is-not-ca":
        after("cloudflare_mtls_certificate.pi_admin_owner_ca")["ca"] = False
    elif name == "certificate-private-key":
        after("cloudflare_mtls_certificate.pi_admin_owner_ca")["private_key"] = (
            "forbidden"
        )
    elif name == "certificate-hash-mismatch":
        variables["owner_device_ca_certificate_sha256"]["value"] = "f" * 64
    elif name == "wrong-certificate-variable":
        config("cloudflare_mtls_certificate.pi_admin_owner_ca")["expressions"][
            "certificates"
        ] = {"references": ["var.unreviewed_certificate"]}
    elif name == "enrollment-everyone":
        selector = after(
            "cloudflare_zero_trust_access_policy.pi_admin_owner_enrollment"
        )["include"][0]
        selector.clear()
        selector["everyone"] = {}
    elif name == "enrollment-email-widened":
        after("cloudflare_zero_trust_access_policy.pi_admin_owner_enrollment")[
            "include"
        ].append({"email_domain": {"domain": "example.invalid"}})
    elif name == "enrollment-mfa-disabled":
        after("cloudflare_zero_trust_access_policy.pi_admin_owner_enrollment")[
            "mfa_config"
        ]["mfa_disabled"] = True
    elif name == "enrollment-weak-mfa":
        after("cloudflare_zero_trust_access_policy.pi_admin_owner_enrollment")[
            "mfa_config"
        ]["allowed_authenticators"] = ["otp"]
    elif name == "enrollment-session-long":
        after("cloudflare_zero_trust_access_policy.pi_admin_owner_enrollment")[
            "session_duration"
        ] = "24h"
    elif name == "wrong-enrollment-email-variable":
        config("cloudflare_zero_trust_access_policy.pi_admin_owner_enrollment")[
            "expressions"
        ]["include"] = {"references": ["var.unreviewed_identity"]}
    elif name == "extra-identity-provider":
        after("cloudflare_zero_trust_access_application.pi_admin_owner_enrollment")[
            "allowed_idps"
        ].append("00000000-0000-0000-0000-000000000000")
    elif name == "enrollment-app-wrong-type":
        after("cloudflare_zero_trust_access_application.pi_admin_owner_enrollment")[
            "type"
        ] = "self_hosted"
    elif name == "enrollment-auto-redirect-off":
        after("cloudflare_zero_trust_access_application.pi_admin_owner_enrollment")[
            "auto_redirect_to_identity"
        ] = False
    elif name == "enrollment-policy-precedence":
        after("cloudflare_zero_trust_access_application.pi_admin_owner_enrollment")[
            "policies"
        ][0]["precedence"] = 2
    elif name == "missing-enrollment-policy-contract":
        variables["verified_admin_enrollment_policy_contract_sha256"]["value"] = ""
    elif name == "wrong-enrollment-policy-variable":
        config("cloudflare_zero_trust_access_application.pi_admin_owner_enrollment")[
            "expressions"
        ]["policies"] = {"references": ["var.unreviewed_policy_id"]}
    elif name == "device-match-widened":
        after("cloudflare_zero_trust_device_custom_profile.pi_admin_owner")[
            "match"
        ] += ' or identity.email == "other@example.invalid"'
    elif name == "device-route-widened":
        after("cloudflare_zero_trust_device_custom_profile.pi_admin_owner")[
            "include"
        ][0]["address"] = "192.168.0.0/16"
    elif name == "device-fallback-enabled":
        after("cloudflare_zero_trust_device_custom_profile.pi_admin_owner")[
            "disable_auto_fallback"
        ] = False
    elif name == "device-dns-registration-enabled":
        after("cloudflare_zero_trust_device_custom_profile.pi_admin_owner")[
            "register_interface_ip_with_dns"
        ] = True
    elif name == "device-wireguard-protocol":
        after("cloudflare_zero_trust_device_custom_profile.pi_admin_owner")[
            "tunnel_protocol"
        ] = "wireguard"
    elif name == "device-can-leave":
        after("cloudflare_zero_trust_device_custom_profile.pi_admin_owner")[
            "allowed_to_leave"
        ] = True
    elif name == "device-can-switch-mode":
        after("cloudflare_zero_trust_device_custom_profile.pi_admin_owner")[
            "allow_mode_switch"
        ] = True
    elif name == "device-private-key-check-off":
        after(
            "cloudflare_zero_trust_device_posture_rule.pi_admin_owner_certificate"
        )["input"]["check_private_key"] = False
    elif name == "device-certificate-cn-wildcard":
        after(
            "cloudflare_zero_trust_device_posture_rule.pi_admin_owner_certificate"
        )["input"]["cn"] = "*"
    elif name == "device-posture-expiration-long":
        after(
            "cloudflare_zero_trust_device_posture_rule.pi_admin_owner_certificate"
        )["expiration"] = "24h"
    elif name == "missing-certificate-contract":
        variables["verified_admin_certificate_contract_sha256"]["value"] = ""
    elif name == "missing-enrollment-contract":
        variables["verified_admin_enrollment_contract_sha256"]["value"] = ""
    elif name == "missing-device-contract":
        variables["verified_admin_device_contract_sha256"]["value"] = ""
    elif name == "opaque-device-profile-id":
        variables["admin_device_profile_id"]["value"] = "opaque_profile"
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
        address = "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow"
        after(address)["rule_settings"]["check_session"]["enforce"] = False
    elif name == "extra-session-setting":
        address = "cloudflare_zero_trust_gateway_policy.pi_admin_ssh_allow"
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
        ]["tunnel_id"] = {"references": ["var.cloudflare_account_id"]}
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
    elif name == "zero-device-contract":
        variables["verified_admin_device_contract_sha256"]["value"] = "0" * 64
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
    elif name == "nonterminal-catchall":
        rules = ingress()
        rules[0], rules[1] = rules[1], rules[0]
    elif name == "wrong-site-origin":
        ingress()[0]["service"] = "http://unreviewed.invalid:8080"
    elif name == "extra-public-tunnel":
        extra_change = copy.deepcopy(exactly_one(changes, tunnel_address()))
        extra_change["address"] = "cloudflare_zero_trust_tunnel_cloudflared.unreviewed"
        extra_change["change"]["after"]["name"] = "unreviewed"
        changes.append(extra_change)
        extra_config = copy.deepcopy(exactly_one(configured, tunnel_address()))
        extra_config["address"] = (
            "cloudflare_zero_trust_tunnel_cloudflared.unreviewed"
        )
        configured.append(extra_config)
    elif name == "public-warp-routing":
        after(
            "cloudflare_zero_trust_tunnel_cloudflared_config.{}".format(
                site()["slug"]
            )
        )["config"]["warp_routing"] = {"enabled": True}
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
    elif name == "wrong-public-hostname":
        after(dns_address())["name"] = "other.invalid"
    elif name == "wrong-zone-variable":
        config(dns_address())["expressions"]["zone_id"] = {
            "references": ["var.cloudflare_account_id"]
        }
    elif name == "unproxied-dns":
        after(dns_address())["proxied"] = False
    elif name == "a-record":
        after(dns_address())["type"] = "A"
    elif name == "aaaa-record":
        after(dns_address())["type"] = "AAAA"
    elif name == "wildcard-dns-name":
        after(dns_address())["name"] = "*." + site()["hostname"]
    elif name == "account-as-zone-target":
        after(dns_address())["zone_id"] = variables[
            "cloudflare_account_id"
        ]["value"]
    elif name == "fabricated-create":
        target = changes[0]["change"]
        target["actions"] = ["create"]
        target["before"] = None
    elif name == "recreate-adopted-tunnel":
        target = exactly_one(changes, tunnel_address())["change"]
        target["actions"] = ["update"]
    elif name == "tunnel-config-update":
        target = exactly_one(changes, tunnel_config_address())["change"]
        target["actions"] = ["update"]
        target["before"]["config"]["ingress"][0]["service"] = (
            "http://unreviewed.invalid:8080"
        )
    elif name == "renamed-tunnel":
        after(tunnel_address())["name"] = "pi-websites"
    elif name == "cross-site-hostname":
        ingress()[0]["hostname"] = site()["foreign_hostname"]
    elif name == "cross-site-origin":
        ingress()[0]["service"] = site()["foreign_origin"]
    elif name == "cross-site-tunnel-reference":
        foreign = "cloudflare_zero_trust_tunnel_cloudflared.{}".format(
            site()["foreign_slug"]
        )
        config(dns_address())["expressions"]["content"] = {
            "references": [foreign + ".id", foreign]
        }
    elif name == "wildcard-hostname":
        ingress()[0]["hostname"] = "*." + site()["hostname"]
    elif name == "extra-ingress-rule":
        ingress().insert(1, {"hostname": "ssh." + site()["hostname"], "service": "ssh://127.0.0.1:22"})
    elif name == "private-route-in-site-root":
        changes.append(
            {
                "address": "cloudflare_zero_trust_tunnel_cloudflared_route.smuggled",
                "mode": "managed",
                "type": "cloudflare_zero_trust_tunnel_cloudflared_route",
                "change": {
                    "actions": ["no-op"],
                    "before": {"network": "192.0.2.10/32"},
                    "after": {"network": "192.0.2.10/32"},
                    "after_unknown": {},
                },
            }
        )
        configured.append(
            {
                "address": "cloudflare_zero_trust_tunnel_cloudflared_route.smuggled",
                "mode": "managed",
                "type": "cloudflare_zero_trust_tunnel_cloudflared_route",
                "expressions": {},
            }
        )
    elif name == "always-use-https-off":
        after(zone_setting("always_use_https"))["value"] = "off"
    elif name == "min-tls-downgrade":
        after(zone_setting("min_tls_version"))["value"] = "1.0"
    elif name == "tls13-off":
        after(zone_setting("tls_1_3"))["value"] = "off"
    elif name == "zero-rtt-on":
        after(zone_setting("zero_rtt"))["value"] = "on"
    elif name == "ssl-strict":
        after(zone_setting("ssl"))["value"] = "strict"
    elif name == "ssl-flexible":
        after(zone_setting("ssl"))["value"] = "flexible"
    elif name == "rebound-zone-setting":
        after(zone_setting("min_tls_version"))["setting_id"] = "security_level"
    elif name == "missing-zone-setting":
        address = zone_setting("always_use_https")
        changes.remove(exactly_one(changes, address))
        configured.remove(exactly_one(configured, address))
    elif name == "extra-zone-setting":
        address = "cloudflare_zone_setting.{}_security_level".format(
            site()["slug"]
        )
        extra_change = copy.deepcopy(exactly_one(changes, zone_setting("ssl")))
        extra_change["address"] = address
        extra_change["change"]["after"]["setting_id"] = "security_level"
        changes.append(extra_change)
        extra_config = copy.deepcopy(exactly_one(configured, zone_setting("ssl")))
        extra_config["address"] = address
        configured.append(extra_config)
    elif name == "duplicate-setting-owner":
        # Copy the managed Always Use HTTPS object under a second address while
        # keeping the same zone and setting_id. Exact desired values are not
        # enough: a second owner would create overlapping state custody.
        source_address = zone_setting("always_use_https")
        address = source_address + "_duplicate"
        extra_change = copy.deepcopy(exactly_one(changes, source_address))
        extra_change["address"] = address
        changes.append(extra_change)
        extra_config = copy.deepcopy(exactly_one(configured, source_address))
        extra_config["address"] = address
        configured.append(extra_config)
    elif name == "wrong-https-prestate":
        exactly_one(changes, zone_setting("always_use_https"))["change"][
            "before"
        ]["value"] = "on"
    elif name == "wrong-min-tls-prestate":
        exactly_one(changes, zone_setting("min_tls_version"))["change"][
            "before"
        ]["value"] = "1.1"
    elif name == "unrelated-zone-setting-update":
        target = exactly_one(changes, zone_setting("tls_1_3"))["change"]
        target["actions"] = ["update"]
        target["before"]["value"] = "off"
    elif name == "lying-no-op-setting":
        # A plan that claims "no-op" on the redirect owner while its own before
        # and after disagree. Every deny rule for this transaction keys on the
        # "update" action, so none of them fires; only the positive transition
        # contract, which requires a no-op to already sit at its target value,
        # can see the lie. This mutation exists to keep that contract provably
        # load-bearing rather than redundant with the deny rules.
        target = exactly_one(changes, zone_setting("always_use_https"))["change"]
        target["actions"] = ["no-op"]
    elif name == "create-with-prior-object":
        # F1 isolation: a create action that KEEPS its prior object. The
        # before-null denial cannot see it and the adopted-identity rule does
        # not apply to a zone setting, so only the adoption-action rule stands
        # between this plan and a duplicated live object.
        exactly_one(changes, zone_setting("ssl"))["change"]["actions"] = ["create"]
    elif name == "apex-foreign-tunnel-uuid":
        # F2 isolation: the configuration still references this root's own
        # Tunnel; only the planned VALUE is foreign. A reference-only binding
        # accepts this forged plan.
        after(dns_address())["content"] = (
            foreign_tunnel_identifier() + ".cfargotunnel.com"
        )
    elif name == "config-foreign-tunnel-uuid":
        after(
            "cloudflare_zero_trust_tunnel_cloudflared_config.{}".format(
                site()["slug"]
            )
        )["tunnel_id"] = foreign_tunnel_identifier()
    elif name == "http3-off":
        after(zone_setting("http3"))["value"] = "off"
    elif name == "cross-site-plan-value":
        # F7 isolation for the planned-value rule: an unpinned provider field
        # carrying the other site's name. Nothing in the exact contract reads
        # it, so this input is otherwise valid.
        after(tunnel_address())["comment"] = "shared with {} until cutover".format(
            site()["foreign_hostname"]
        )
    elif name == "cross-site-ingress-value":
        # F7 isolation for the ingress rule: an ingress block attached to a
        # resource whose exact contract does not pin extra keys.
        after(tunnel_address())["config"] = {
            "ingress": [{"service": site()["foreign_origin"]}]
        }
    elif name == "cross-site-config-reference":
        # F7 isolation for the reference rule: a field whose references no
        # exact-reference assertion inspects.
        config(tunnel_address())["expressions"]["name"] = {
            "references": [site()["foreign_variable"]]
        }
    elif name == "missing-adoption-audit":
        variables[site()["audit_variable"]]["value"] = ""
    elif name == "zero-adoption-audit":
        variables[site()["audit_variable"]]["value"] = "0" * 64
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
