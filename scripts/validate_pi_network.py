#!/usr/bin/env python3
"""Fail closed unless kubeadm CIDRs are separated from a simple LAN route model."""

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path


# DEFAULT_IPV4_RULES is the only policy-routing model this bootstrap can prove;
# VPN-specific priorities or tables require a new human network decision.
DEFAULT_IPV4_RULES = frozenset(
    (
        (0, "all", "local"),
        (32766, "all", "main"),
        (32767, "all", "default"),
    )
)

# TABLE_NAMES normalizes iproute2's numeric and textual names before exact checks.
TABLE_NAMES = {
    "253": "default",
    "254": "main",
    "255": "local",
    253: "default",
    254: "main",
    255: "local",
}

# These link kinds alter packet paths without an ordinary LAN gateway. Refuse
# them instead of guessing whether a VPN's routes and policy rules are benign.
TUNNEL_LINK_KINDS = frozenset(
    (
        "erspan",
        "gre",
        "gretap",
        "ip6gre",
        "ip6gretap",
        "ipip",
        "l2tp",
        "macsec",
        "ppp",
        "sit",
        "tap",
        "tun",
        "vti",
        "vti6",
        "wireguard",
        "xfrm",
    )
)

# TUNNEL_INTERFACE_NAME uses protocol- and role-shaped names rather than vendor
# names, so detection stays useful without recording private product choices.
TUNNEL_INTERFACE_NAME = re.compile(
    r"(?:^|[-_.])(?:"
    r"corp-vpn|ipsec|ppp\d*|tap\d*|tun\d*|utun\d*|vpn\d*|warp\d*|wg\d*|"
    r"wireguard\d*|xfrm\d*"
    r")(?:$|[-_.])",
    flags=re.IGNORECASE,
)

# These route indirections need more topology reasoning than the simple LAN model
# provides, so their presence blocks kubeadm rather than being approximated.
UNSUPPORTED_ROUTE_KEYS = frozenset(("encap", "multipath", "nexthops", "nhid", "via"))


# one extracts a single network field from the already strict kubeadm template;
# missing or duplicated values make the live comparison ambiguous.
def one(pattern, text, label):
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("expected exactly one {}".format(label))
    return matches[0]


# ip_json asks iproute2 for structured IPv4 state, avoiding locale- and spacing-
# dependent parsing of the host's routes and addresses.
def ip_json(*arguments):
    completed = subprocess.run(
        ["ip", "-j", "-4", *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(completed.stdout)


# require_json_list validates each iproute2 collection before individual fields
# are trusted as bootstrap evidence.
def require_json_list(value, label):
    if not isinstance(value, list):
        raise ValueError("{} query did not return a JSON list".format(label))
    if any(not isinstance(item, dict) for item in value):
        raise ValueError("{} query returned a non-object entry".format(label))
    return value


# normalize_table gives the route and rule checks one canonical table identity.
def normalize_table(value):
    value = TABLE_NAMES.get(value, value)
    if isinstance(value, str):
        value = value.strip().lower()
    return value


# validate_default_ipv4_rules refuses policy routing because an extra rule could
# redirect cluster CIDRs through a VPN despite an apparently safe main table.
def validate_default_ipv4_rules(rules):
    observed = []
    allowed_keys = frozenset(("flags", "priority", "protocol", "src", "table"))
    for rule in require_json_list(rules, "IPv4 rule"):
        unexpected = sorted(set(rule) - allowed_keys)
        if unexpected:
            raise ValueError(
                "unsupported IPv4 policy rule fields: {}".format(", ".join(unexpected))
            )
        flags = rule.get("flags", [])
        if flags not in (None, []):
            raise ValueError("IPv4 policy rule has unsupported flags")
        try:
            priority = int(rule["priority"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("IPv4 policy rule has no exact numeric priority")
        source = rule.get("src")
        if source == "0.0.0.0/0":
            source = "all"
        table = normalize_table(rule.get("table"))
        observed.append((priority, source, table))

    if len(observed) != len(DEFAULT_IPV4_RULES) or frozenset(observed) != DEFAULT_IPV4_RULES:
        raise ValueError(
            "IPv4 policy rules differ from the canonical local/main/default rules"
        )


# parse_links indexes interface kind and type so every route can be checked for a
# tunnel without relying only on its human-assigned name.
def parse_links(links):
    parsed = {}
    for link in require_json_list(links, "IPv4 link"):
        name = link.get("ifname")
        if not isinstance(name, str) or not name:
            raise ValueError("IPv4 link has no interface name")
        if name in parsed:
            raise ValueError("IPv4 link query returned duplicate interface {}".format(name))
        link_type = link.get("link_type")
        if link_type is not None and not isinstance(link_type, str):
            raise ValueError("IPv4 link {} has an invalid link type".format(name))
        link_info = link.get("linkinfo", {})
        if link_info is None:
            link_info = {}
        if not isinstance(link_info, dict):
            raise ValueError("IPv4 link {} has invalid detailed link data".format(name))
        kind = link_info.get("info_kind")
        if kind is not None and not isinstance(kind, str):
            raise ValueError("IPv4 link {} has an invalid link kind".format(name))
        parsed[name] = (
            kind.lower() if kind else None,
            link_type.lower() if link_type else None,
        )
    return parsed


# parse_addresses inventories connected networks and proves the kubeadm advertise
# address is bound exactly once to a known live interface.
def parse_addresses(addresses, advertise, links):
    networks = []
    advertise_bindings = []
    for interface in require_json_list(addresses, "IPv4 address"):
        name = interface.get("ifname")
        address_info = interface.get("addr_info")
        if not isinstance(name, str) or not name:
            raise ValueError("IPv4 address entry has no interface name")
        if name not in links:
            raise ValueError(
                "IPv4 address query references interface absent from link query: {}".format(name)
            )
        if not isinstance(address_info, list):
            raise ValueError("IPv4 address entry for {} has invalid addr_info".format(name))
        for address in address_info:
            if not isinstance(address, dict):
                raise ValueError("IPv4 address entry for {} is not an object".format(name))
            if address.get("family") != "inet":
                continue
            try:
                local = ipaddress.ip_address(address["local"])
                network = ipaddress.ip_network(
                    "{}/{}".format(local, address["prefixlen"]), strict=False
                )
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("invalid IPv4 address on {}: {}".format(name, error))
            if local.version != 4 or network.version != 4:
                raise ValueError("non-IPv4 address returned by IPv4 address query")
            networks.append(("interface {}".format(name), network))
            if local == advertise:
                advertise_bindings.append((name, network))

    if len(advertise_bindings) != 1:
        raise ValueError(
            "advertise address must occur exactly once in the live IPv4 address inventory"
        )
    return networks, advertise_bindings[0]


# link_is_tunnel combines kernel metadata and conservative naming heuristics; any
# positive result stops the simple-LAN proof.
def link_is_tunnel(interface, links):
    if interface not in links:
        raise ValueError("route references interface absent from IPv4 link query: {}".format(interface))
    kind, link_type = links[interface]
    if kind in TUNNEL_LINK_KINDS or link_type in TUNNEL_LINK_KINDS or link_type == "none":
        return True
    return bool(TUNNEL_INTERFACE_NAME.search(interface))


# parse_route_network normalizes default and explicit destinations to IPv4Network
# objects used by the overlap checks.
def parse_route_network(destination):
    if not isinstance(destination, str) or not destination:
        raise ValueError("route has no exact IPv4 destination")
    if destination == "default":
        return ipaddress.ip_network("0.0.0.0/0")
    try:
        network = ipaddress.ip_network(destination, strict=False)
    except ValueError as error:
        raise ValueError("invalid IPv4 route destination {}: {}".format(destination, error))
    if network.version != 4:
        raise ValueError("non-IPv4 route returned by IPv4 route query")
    return network


# validate_default_route ties the sole default gateway to the same LAN interface
# and source address selected for the Kubernetes API server.
def validate_default_route(route, advertise, advertise_binding):
    interface, lan_network = advertise_binding
    if route.get("dev") != interface:
        raise ValueError("default route is not on the advertise-address LAN interface")
    try:
        gateway = ipaddress.ip_address(route["gateway"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("default route has no exact IPv4 LAN gateway proof")
    if gateway.version != 4 or gateway not in lan_network or gateway == advertise:
        raise ValueError("default route gateway is not a distinct address on the advertise LAN")
    preferred_source = route.get("prefsrc")
    if preferred_source is not None:
        try:
            if ipaddress.ip_address(preferred_source) != advertise:
                raise ValueError("default route preferred source is not the advertise address")
        except (TypeError, ValueError):
            raise ValueError("default route has an invalid preferred source")
    flags = route.get("flags", [])
    if flags not in (None, []):
        raise ValueError("default route has unsupported flags")


# live_networks returns every relevant connected and routed network only after the
# host has satisfied the repository's deliberately simple, policy-free LAN model.
def live_networks(advertise):
    """Return routable networks after proving a simple, policy-free LAN model."""
    if not isinstance(advertise, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        advertise = ipaddress.ip_address(advertise)
    if advertise.version != 4:
        raise ValueError("advertise address must be IPv4")

    # Each query is mandatory. Malformed or unavailable state is uncertainty,
    # and uncertainty must stop bootstrap rather than weaken the overlap proof.
    addresses = ip_json("address", "show")
    links = parse_links(ip_json("-details", "link", "show"))
    validate_default_ipv4_rules(ip_json("rule", "show"))
    routes = require_json_list(ip_json("route", "show", "table", "all"), "IPv4 route")

    networks, advertise_binding = parse_addresses(addresses, advertise, links)
    default_routes = 0
    for route in routes:
        unsupported = sorted(set(route) & UNSUPPORTED_ROUTE_KEYS)
        if unsupported:
            raise ValueError(
                "route uses unsupported indirection: {}".format(", ".join(unsupported))
            )
        table = normalize_table(route.get("table", "main"))
        if table not in ("local", "main"):
            raise ValueError("unsupported route table {}".format(table))
        network = parse_route_network(route.get("dst"))
        route_type = route.get("type", "unicast")

        if table == "local":
            if network.prefixlen == 0 or route_type not in ("broadcast", "local"):
                raise ValueError("local table contains a non-local route")
            networks.append(("route table local", network))
            continue

        if route_type != "unicast":
            raise ValueError("main table contains unsupported route type {}".format(route_type))
        interface = route.get("dev")
        if not isinstance(interface, str) or not interface:
            raise ValueError("main-table route has no exact output interface")
        if link_is_tunnel(interface, links):
            raise ValueError("VPN/tunnel route detected on interface {}".format(interface))

        if network.prefixlen == 0:
            default_routes += 1
            validate_default_route(route, advertise, advertise_binding)
            continue

        # Do not discard broad routes. /1 split-defaults and /2-/7 aggregate
        # routes can capture cluster traffic just as effectively as /8 routes.
        networks.append(("route table main", network))

    if default_routes > 1:
        raise ValueError("more than one IPv4 default route prevents an exact LAN route proof")
    return networks


# main compares the reviewed pod/service CIDRs with current host state immediately
# before bootstrap, converting uncertainty or drift into a hard failure.
def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    args = parser.parse_args(argv)
    text = args.config.read_text(encoding="utf-8")
    try:
        pod = ipaddress.ip_network(one(r"^\s{2}podSubnet:\s*(\S+)\s*$", text, "podSubnet"))
        service = ipaddress.ip_network(
            one(r"^\s{2}serviceSubnet:\s*(\S+)\s*$", text, "serviceSubnet")
        )
        advertise = ipaddress.ip_address(
            one(r"^\s{2}advertiseAddress:\s*(\S+)\s*$", text, "advertiseAddress")
        )
        if pod.version != 4 or service.version != 4 or advertise.version != 4:
            raise ValueError("pod, service, and advertise networks must all be IPv4")
        current = live_networks(advertise)
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        print("FAIL unable to prove live network separation: {}".format(error), file=sys.stderr)
        return 1
    failures = []
    if pod.overlaps(service):
        failures.append("pod and service CIDRs overlap")
    if not advertise.is_private or advertise.is_loopback or advertise.is_link_local:
        failures.append("API advertise address is not a private unicast address")
    for target_name, target in (("pod", pod), ("service", service)):
        for source, network in current:
            if target.overlaps(network):
                failures.append(
                    "{} CIDR {} overlaps {} {}".format(target_name, target, source, network)
                )
    for failure in sorted(set(failures)):
        print("FAIL " + failure, file=sys.stderr)
    if failures:
        return 1
    print("PASS pod and service CIDRs are separated under the canonical LAN route model")
    return 0


if __name__ == "__main__":
    sys.exit(main())
