"""Adversarial matrix for the SSH-only ingress-guard semantic verifier.

Every fixture is a structured `nft -a -j` document assembled at runtime (never
a tracked host capture), and every dangerous shape the handoff enumerates —
partial port coverage, SSH inclusion, destination-only rules, wildcard or
multi-interface overreach, alternate tables, set/verdict-map indirection,
inversion, malformed encodings, single-family variants, decoy chains,
priority/policy/hook drift, foreign objects, unknown grammar — must map to
a fixed value-free failure token. The healthy model must pass exactly.
"""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .support import load_script

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_ingress_guard.py"

MODULE = load_script("validate_ingress_guard.py")

TABLE = MODULE.OWNED_TABLE
CHAIN = MODULE.OWNED_CHAIN

# The complete failure vocabulary of the model/absence engines. The final
# test refuses any diagnostic outside this closed set.
MODEL_TOKENS = frozenset({
    "RULESET_JSON_INVALID",
    "SCHEMA_VERSION_UNSUPPORTED",
    "TABLE_MISSING",
    "TABLE_DUPLICATE",
    "TABLE_GRAMMAR_UNSUPPORTED",
    "TABLE_FAMILY_INVALID",
    "FOREIGN_OBJECT_IN_OWNED_TABLE",
    "CHAIN_MISSING",
    "CHAIN_UNEXPECTED",
    "CHAIN_NAME_COLLISION",
    "CHAIN_GRAMMAR_UNSUPPORTED",
    "CHAIN_TYPE_INVALID",
    "HOOK_INVALID",
    "PRIORITY_INVALID",
    "POLICY_INVALID",
    "RULE_PLACEMENT_INVALID",
    "RULE_GRAMMAR_UNSUPPORTED",
    "RULE_HANDLE_DUPLICATE",
    "MATCH_INVERSION_UNSUPPORTED",
    "SET_INDIRECTION_UNSUPPORTED",
    "WILDCARD_UNSUPPORTED",
    "COUNTER_MISSING",
    "VERDICT_UNSUPPORTED",
    "SSH_PRESERVATION_VIOLATED",
    "DENY_WIDENING_ACCEPT",
    "INTERFACE_OVERREACH",
    "COVERAGE_INCOMPLETE",
    "COVERAGE_DUPLICATE",
    "RULE_ORDER_INVALID",
    "PREEXISTING_OWNED_TABLE",
})


def rule(iface, port, verdict, family="inet", chain=CHAIN, table=TABLE, expr=None):
    if expr is None:
        expr = [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": iface}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": port}},
            {"counter": {"packets": 0, "bytes": 0}},
            {verdict: None},
        ]
    return {"rule": {"family": family, "table": table, "chain": chain, "handle": 7, "expr": expr}}


def metainfo(schema_version=1):
    return {
        "metainfo": {
            "version": "1.0.9",
            "release_name": "synthetic",
            "json_schema_version": schema_version,
        }
    }


def document(rules, family="inet", prio=-10, policy="accept", hook="input",
             chain_type="filter", chain_name=CHAIN, extra=(), chain_extra=None,
             schema_version=1):
    chain = {
        "family": family, "table": TABLE, "name": chain_name, "handle": 1,
        "type": chain_type, "hook": hook, "prio": prio, "policy": policy,
    }
    if chain_extra:
        chain.update(chain_extra)
    if chain_type is None:
        for key in ("type", "hook", "prio", "policy"):
            chain.pop(key, None)
    items = [
        metainfo(schema_version),
        {"table": {"family": family, "name": TABLE, "handle": 20}},
        {"chain": chain},
    ]
    for index, item in enumerate(rules, start=100):
        item = copy.deepcopy(item)
        if "rule" in item:
            item["rule"]["handle"] = index
        items.append(item)
    items.extend(extra)
    return {"nftables": items}


def healthy(interfaces=("adminvpn0",)):
    return document(
        [rule(iface, port, verdict)
         for iface, port, verdict in MODULE.expected_sequence(interfaces)]
    )


def errors(doc, interfaces=("adminvpn0",)):
    return MODULE.model_errors(doc, tuple(interfaces))


class HealthyModelTests(unittest.TestCase):
    def test_exact_healthy_model_passes_for_one_and_many_interfaces(self):
        self.assertEqual(errors(healthy()), [])
        many = ("adminvpn0", "adminvpn1")
        self.assertEqual(errors(healthy(many), many), [])

    def test_expected_sequence_is_ssh_first_then_all_four_denials(self):
        sequence = MODULE.expected_sequence(("adminvpn0",))
        self.assertEqual(sequence[0], ("adminvpn0", 22, "accept"))
        self.assertEqual(
            [entry[1:] for entry in sequence[1:]],
            [(2379, "drop"), (2380, "drop"), (6443, "drop"), (10250, "drop")],
        )

    def test_render_is_deterministic_and_matches_the_closed_grammar(self):
        first = MODULE.render_text(("adminvpn0",))
        self.assertEqual(first, MODULE.render_text(("adminvpn0",)))
        self.assertIn('table inet %s {' % TABLE, first)
        self.assertIn("type filter hook input priority -10; policy accept;", first)
        for port, verdict in ((22, "accept"), (2379, "drop"), (2380, "drop"),
                              (6443, "drop"), (10250, "drop")):
            self.assertIn(
                'iifname "adminvpn0" tcp dport %d counter %s' % (port, verdict), first
            )
        self.assertNotIn("flush", first)


class GuardModelAdversarialTests(unittest.TestCase):
    """Each dangerous state maps to its fixed token (spec adversarial matrix)."""

    def assertToken(self, doc, token, interfaces=("adminvpn0",)):
        observed = errors(doc, interfaces)
        self.assertIn(token, observed, f"expected {token}, observed {observed}")

    def test_ruleset_envelope_and_metainfo_grammar_are_exact(self):
        self.assertToken({}, "RULESET_JSON_INVALID")

        extra_top_level = healthy()
        extra_top_level["future"] = {}
        self.assertToken(extra_top_level, "RULESET_JSON_INVALID")

        two_member_item = healthy()
        two_member_item["nftables"].append(
            {"future": {}, "another_future": {}}
        )
        self.assertToken(two_member_item, "RULESET_JSON_INVALID")

        empty_item = healthy()
        empty_item["nftables"].append({})
        self.assertToken(empty_item, "RULESET_JSON_INVALID")

        non_object_body = healthy()
        non_object_body["nftables"].append({"future": []})
        self.assertToken(non_object_body, "RULESET_JSON_INVALID")
        self.assertEqual(
            MODULE.absence_errors(
                {"nftables": [metainfo(), {"future": []}]}
            ),
            ["RULESET_JSON_INVALID"],
        )

        reordered = healthy()
        metadata_item = reordered["nftables"].pop(0)
        reordered["nftables"].insert(1, metadata_item)
        self.assertToken(reordered, "SCHEMA_VERSION_UNSUPPORTED")

        for missing_key in ("version", "release_name", "json_schema_version"):
            with self.subTest(missing_metainfo_key=missing_key):
                candidate = healthy()
                del candidate["nftables"][0]["metainfo"][missing_key]
                self.assertToken(candidate, "SCHEMA_VERSION_UNSUPPORTED")

        for key, value in (
            ("future", "unsupported"),
            ("version", ""),
            ("version", True),
            ("version", 1),
            ("release_name", ""),
            ("release_name", True),
            ("release_name", 1),
        ):
            with self.subTest(metainfo_key=key, value=value):
                candidate = healthy()
                candidate["nftables"][0]["metainfo"][key] = value
                self.assertToken(candidate, "SCHEMA_VERSION_UNSUPPORTED")

    def test_owned_table_grammar_is_exact_and_active(self):
        for missing_key in ("family", "name", "handle"):
            with self.subTest(missing_table_key=missing_key):
                candidate = healthy()
                del candidate["nftables"][1]["table"][missing_key]
                self.assertToken(candidate, "RULESET_JSON_INVALID")

        for key, value in (
            ("flags", "dormant"),
            ("flags", ["dormant"]),
            ("flags", "owner"),
            ("flags", ["owner"]),
            ("flags", "persist"),
            ("flags", ["persist"]),
            ("flags", []),
            ("comment", "looks-active"),
            ("future", "unsupported"),
        ):
            with self.subTest(table_key=key, value=value):
                candidate = healthy()
                candidate["nftables"][1]["table"][key] = value
                self.assertToken(candidate, "TABLE_GRAMMAR_UNSUPPORTED")

        for handle in (0, -1, True, 1.0, "1", 2**64):
            with self.subTest(table_handle=handle):
                candidate = healthy()
                candidate["nftables"][1]["table"]["handle"] = handle
                self.assertToken(candidate, "RULESET_JSON_INVALID")

        maximum = healthy()
        maximum["nftables"][1]["table"]["handle"] = 2**64 - 1
        self.assertEqual(errors(maximum), [])

    def test_owned_chain_keys_handles_and_priority_are_exact(self):
        required_keys = {
            "family": "RULESET_JSON_INVALID",
            "name": "RULESET_JSON_INVALID",
            "handle": "RULESET_JSON_INVALID",
            "type": "CHAIN_GRAMMAR_UNSUPPORTED",
            "hook": "CHAIN_GRAMMAR_UNSUPPORTED",
            "prio": "CHAIN_GRAMMAR_UNSUPPORTED",
            "policy": "CHAIN_GRAMMAR_UNSUPPORTED",
        }
        for missing_key, token in required_keys.items():
            with self.subTest(missing_chain_key=missing_key):
                candidate = healthy()
                del candidate["nftables"][2]["chain"][missing_key]
                self.assertToken(candidate, token)

        missing_table = healthy()
        del missing_table["nftables"][2]["chain"]["table"]
        self.assertToken(missing_table, "RULESET_JSON_INVALID")

        for key in ("newname", "dev", "comment", "flags", "future"):
            with self.subTest(extra_chain_key=key):
                candidate = healthy()
                candidate["nftables"][2]["chain"][key] = "unsupported"
                self.assertToken(candidate, "CHAIN_GRAMMAR_UNSUPPORTED")

        for handle in (0, -1, True, 1.0, "1", 2**64):
            with self.subTest(chain_handle=handle):
                candidate = healthy()
                candidate["nftables"][2]["chain"]["handle"] = handle
                self.assertToken(candidate, "RULESET_JSON_INVALID")

        for priority in (-10.0, True, "-10"):
            with self.subTest(chain_priority=priority):
                candidate = healthy()
                candidate["nftables"][2]["chain"]["prio"] = priority
                self.assertToken(candidate, "PRIORITY_INVALID")

        maximum = healthy()
        maximum["nftables"][2]["chain"]["handle"] = 2**64 - 1
        self.assertEqual(errors(maximum), [])

    def test_owned_rule_keys_and_handles_are_exact(self):
        for missing_key in ("family", "table", "chain", "handle", "expr"):
            with self.subTest(missing_rule_key=missing_key):
                candidate = healthy()
                del candidate["nftables"][3]["rule"][missing_key]
                self.assertToken(candidate, "RULESET_JSON_INVALID")

        for key in ("index", "comment", "future"):
            with self.subTest(extra_rule_key=key):
                candidate = healthy()
                candidate["nftables"][3]["rule"][key] = "unsupported"
                self.assertToken(candidate, "RULE_GRAMMAR_UNSUPPORTED")

        for handle in (0, -1, True, 1.0, "1", 2**64):
            with self.subTest(rule_handle=handle):
                candidate = healthy()
                candidate["nftables"][3]["rule"]["handle"] = handle
                self.assertToken(candidate, "RULESET_JSON_INVALID")

        maximum = healthy()
        maximum["nftables"][3]["rule"]["handle"] = 2**64 - 1
        self.assertEqual(errors(maximum), [])

    def test_owned_rule_handles_are_unique_within_the_owned_chain(self):
        candidate = healthy()
        candidate["nftables"][4]["rule"]["handle"] = (
            candidate["nftables"][3]["rule"]["handle"]
        )
        self.assertToken(candidate, "RULE_HANDLE_DUPLICATE")

    def test_adjacent_known_object_identities_fail_before_ownership_filtering(self):
        valid_objects = {
            "table": {
                "table": {"family": "ip", "name": "foreign", "handle": 1}
            },
            "chain": {"chain": {
                "family": "ip", "table": "foreign", "name": "foreign_chain",
                "handle": 2,
            }},
            "rule": {"rule": {
                "family": "ip", "table": "foreign", "chain": "foreign_chain",
                "handle": 3, "expr": [],
            }},
        }
        required_keys = {
            "table": ("family", "name", "handle"),
            "chain": ("family", "table", "name", "handle"),
            "rule": ("family", "table", "chain", "handle", "expr"),
        }
        string_keys = {
            "table": ("family", "name"),
            "chain": ("family", "table", "name"),
            "rule": ("family", "table", "chain"),
        }
        malformed = []
        for kind, item in valid_objects.items():
            for key in required_keys[kind]:
                candidate = copy.deepcopy(item)
                del candidate[kind][key]
                malformed.append((kind + "-missing-" + key, candidate))
            for key in string_keys[kind]:
                candidate = copy.deepcopy(item)
                candidate[kind][key] = True
                malformed.append((kind + "-boolean-" + key, candidate))
                candidate = copy.deepcopy(item)
                candidate[kind][key] = ""
                malformed.append((kind + "-empty-" + key, candidate))
            for handle in (0, -1, True, 1.0, "1", 2**64):
                candidate = copy.deepcopy(item)
                candidate[kind]["handle"] = handle
                malformed.append((kind + "-invalid-handle-" + str(handle), candidate))
        wrong_expr = copy.deepcopy(valid_objects["rule"])
        wrong_expr["rule"]["expr"] = True
        malformed.append(("rule-boolean-expr", wrong_expr))

        for label, item in malformed:
            with self.subTest(mode="model", case=label):
                candidate = healthy()
                candidate["nftables"].append(copy.deepcopy(item))
                self.assertToken(candidate, "RULESET_JSON_INVALID")
            with self.subTest(mode="absence", case=label):
                candidate = {"nftables": [metainfo(), copy.deepcopy(item)]}
                self.assertEqual(
                    MODULE.absence_errors(candidate),
                    ["RULESET_JSON_INVALID"],
                )

        for kind, item in valid_objects.items():
            maximum = copy.deepcopy(item)
            maximum[kind]["handle"] = 2**64 - 1
            with self.subTest(mode="model", case=kind + "-maximum-handle"):
                candidate = healthy()
                candidate["nftables"].append(copy.deepcopy(maximum))
                self.assertEqual(errors(candidate), [])
            with self.subTest(mode="absence", case=kind + "-maximum-handle"):
                candidate = {"nftables": [metainfo(), maximum]}
                self.assertEqual(MODULE.absence_errors(candidate), [])

    def test_anonymous_counter_output_grammar_is_exact_uint64(self):
        counter_cases = (
            {},
            {"packets": 0},
            {"bytes": 0},
            {"packets": 0, "bytes": 0, "future": 0},
            {"packets": True, "bytes": 0},
            {"packets": 0, "bytes": True},
            {"packets": 0.0, "bytes": 0},
            {"packets": 0, "bytes": 0.0},
            {"packets": "0", "bytes": 0},
            {"packets": 0, "bytes": "0"},
            {"packets": -1, "bytes": 0},
            {"packets": 0, "bytes": -1},
            {"packets": 2**64, "bytes": 0},
            {"packets": 0, "bytes": 2**64},
        )
        for counter in counter_cases:
            with self.subTest(counter=counter):
                candidate = healthy()
                candidate["nftables"][3]["rule"]["expr"][2]["counter"] = counter
                self.assertToken(candidate, "RULE_GRAMMAR_UNSUPPORTED")

        maximum = healthy()
        for item in maximum["nftables"]:
            if "rule" in item:
                item["rule"]["expr"][2]["counter"] = {
                    "packets": 2**64 - 1,
                    "bytes": 2**64 - 1,
                }
        self.assertEqual(errors(maximum), [])

    def test_missing_table_fails(self):
        doc = {"nftables": [metainfo()]}
        self.assertToken(doc, "TABLE_MISSING")

    def test_duplicate_owned_tables_fail(self):
        doc = healthy()
        doc["nftables"].append({"table": {"family": "ip", "name": TABLE, "handle": 9}})
        self.assertToken(doc, "TABLE_DUPLICATE")

    def test_single_family_variants_fail(self):
        for family in ("ip", "ip6"):
            with self.subTest(family=family):
                rules = [rule(i, p, v, family=family)
                         for i, p, v in MODULE.expected_sequence(("adminvpn0",))]
                self.assertToken(
                    document(rules, family=family), "TABLE_FAMILY_INVALID"
                )

    def test_missing_or_renamed_chain_fails(self):
        doc = {"nftables": [
            metainfo(),
            {"table": {"family": "inet", "name": TABLE, "handle": 20}},
        ]}
        self.assertToken(doc, "CHAIN_MISSING")
        renamed = document([], chain_name="admin_ingress_v2")
        self.assertToken(renamed, "CHAIN_MISSING")

    def test_second_chain_in_owned_table_fails(self):
        doc = healthy()
        doc["nftables"].append({"chain": {
            "family": "inet", "table": TABLE, "name": "spare", "handle": 2,
            "type": "filter", "hook": "input", "prio": -5, "policy": "accept",
        }})
        self.assertToken(doc, "CHAIN_UNEXPECTED")

    def test_same_named_decoy_chain_in_foreign_table_fails(self):
        doc = healthy()
        doc["nftables"].append({"chain": {
            "family": "ip", "table": "filter", "name": CHAIN, "handle": 3,
            "type": "filter", "hook": "input", "prio": 0, "policy": "accept",
        }})
        self.assertToken(doc, "CHAIN_NAME_COLLISION")

    def test_wrong_hook_priority_policy_type_or_non_base_chain_fail(self):
        base = MODULE.expected_sequence(("adminvpn0",))
        rules = [rule(i, p, v) for i, p, v in base]
        self.assertToken(document(rules, hook="output"), "HOOK_INVALID")
        self.assertToken(document(rules, prio=0), "PRIORITY_INVALID")
        self.assertToken(document(rules, prio="filter"), "PRIORITY_INVALID")
        self.assertToken(document(rules, policy="drop"), "POLICY_INVALID")
        self.assertToken(document(rules, chain_type="route"), "CHAIN_TYPE_INVALID")
        self.assertToken(document(rules, chain_type=None), "HOOK_INVALID")

    def test_unknown_chain_key_fails(self):
        doc = document([], chain_extra={"dev": "adminvpn0"})
        self.assertToken(doc, "CHAIN_GRAMMAR_UNSUPPORTED")

    def test_only_three_of_four_protected_ports_fail(self):
        rules = [rule(i, p, v)
                 for i, p, v in MODULE.expected_sequence(("adminvpn0",))[:-1]]
        self.assertToken(document(rules), "COVERAGE_INCOMPLETE")

    def test_missing_ssh_preservation_rule_fails(self):
        rules = [rule(i, p, v)
                 for i, p, v in MODULE.expected_sequence(("adminvpn0",))[1:]]
        self.assertToken(document(rules), "COVERAGE_INCOMPLETE")

    def test_ssh_22_inside_the_deny_set_fails(self):
        rules = [rule("adminvpn0", 22, "drop")] + [
            rule(i, p, v) for i, p, v in MODULE.expected_sequence(("adminvpn0",))[1:]
        ]
        self.assertToken(document(rules), "SSH_PRESERVATION_VIOLATED")

    def test_accept_before_drop_widening_fails(self):
        widened = [rule("adminvpn0", 6443, "accept")] + [
            rule(i, p, v) for i, p, v in MODULE.expected_sequence(("adminvpn0",))
        ]
        self.assertToken(document(widened), "DENY_WIDENING_ACCEPT")

    def test_destination_only_rule_without_interface_binding_fails(self):
        expr = [
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 6443}},
            {"counter": {"packets": 0, "bytes": 0}},
            {"drop": None},
        ]
        rules = [rule("adminvpn0", 0, "drop", expr=expr)]
        self.assertToken(document(rules), "RULE_GRAMMAR_UNSUPPORTED")

    def test_wildcard_interface_match_fails(self):
        rules = [rule("adminvpn*", p, v)
                 for _, p, v in MODULE.expected_sequence(("adminvpn0",))]
        self.assertToken(document(rules), "WILDCARD_UNSUPPORTED")

    def test_undeclared_interface_overreach_fails(self):
        doc = healthy()
        doc["nftables"].append(rule("adminvpn9", 6443, "drop"))
        self.assertToken(doc, "INTERFACE_OVERREACH")

    def test_partially_covered_interface_set_fails(self):
        both = ("adminvpn0", "adminvpn1")
        self.assertToken(healthy(("adminvpn0",)), "COVERAGE_INCOMPLETE", both)

    def test_anonymous_set_indirection_fails(self):
        expr = [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "adminvpn0"}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": {"set": [2379, 2380, 6443, 10250]}}},
            {"counter": {"packets": 0, "bytes": 0}},
            {"drop": None},
        ]
        self.assertToken(document([rule("adminvpn0", 0, "drop", expr=expr)]),
                         "SET_INDIRECTION_UNSUPPORTED")

    def test_verdict_map_and_jump_indirection_fail(self):
        vmap_expr = [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "adminvpn0"}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 6443}},
            {"counter": {"packets": 0, "bytes": 0}},
            {"vmap": {"key": {"meta": {"key": "iifname"}}, "data": []}},
        ]
        self.assertToken(document([rule("adminvpn0", 0, "drop", expr=vmap_expr)]),
                         "VERDICT_UNSUPPORTED")
        jump_expr = vmap_expr[:3] + [{"jump": {"target": "spare"}}]
        self.assertToken(document([rule("adminvpn0", 0, "drop", expr=jump_expr)]),
                         "VERDICT_UNSUPPORTED")

    def test_match_inversion_fails(self):
        expr = [
            {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "adminvpn0"}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 6443}},
            {"counter": {"packets": 0, "bytes": 0}},
            {"drop": None},
        ]
        self.assertToken(document([rule("adminvpn0", 0, "drop", expr=expr)]),
                         "MATCH_INVERSION_UNSUPPORTED")

    def test_boolean_null_and_malformed_encodings_fail(self):
        self.assertEqual(errors("not-a-document"), ["RULESET_JSON_INVALID"])
        self.assertEqual(errors({"nftables": "x"}), ["RULESET_JSON_INVALID"])
        self.assertEqual(errors({"nftables": [[]]}), ["RULESET_JSON_INVALID"])
        boolean_port = [rule("adminvpn0", True, "drop")]
        self.assertToken(document(boolean_port), "RULE_GRAMMAR_UNSUPPORTED")
        null_port = [rule("adminvpn0", None, "drop")]
        self.assertToken(document(null_port), "RULE_GRAMMAR_UNSUPPORTED")
        boolean_priority = [rule(i, p, v)
                            for i, p, v in MODULE.expected_sequence(("adminvpn0",))]
        self.assertToken(document(boolean_priority, prio=True), "PRIORITY_INVALID")

    def test_missing_counter_fails(self):
        expr = [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "adminvpn0"}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 6443}},
            {"log": {}},
            {"drop": None},
        ]
        self.assertToken(document([rule("adminvpn0", 0, "drop", expr=expr)]),
                         "COUNTER_MISSING")

    def test_foreign_object_bound_to_owned_table_fails(self):
        doc = healthy()
        doc["nftables"].append({"set": {
            "family": "inet", "table": TABLE, "name": "ports", "handle": 30,
            "type": "inet_service",
        }})
        self.assertToken(doc, "FOREIGN_OBJECT_IN_OWNED_TABLE")

    def test_port_outside_the_closed_model_fails(self):
        doc = healthy()
        doc["nftables"].append(rule("adminvpn0", 8443, "drop"))
        self.assertToken(doc, "RULE_GRAMMAR_UNSUPPORTED")

    def test_duplicate_rule_fails(self):
        doc = healthy()
        doc["nftables"].append(rule("adminvpn0", 6443, "drop"))
        self.assertToken(doc, "COVERAGE_DUPLICATE")

    def test_scrambled_rule_order_fails(self):
        sequence = MODULE.expected_sequence(("adminvpn0",))
        scrambled = [rule(i, p, v) for i, p, v in sequence[1:] + sequence[:1]]
        self.assertToken(document(scrambled), "RULE_ORDER_INVALID")

    def test_unknown_rule_key_fails(self):
        tampered = rule("adminvpn0", 22, "accept")
        tampered["rule"]["comment"] = "looks-official"
        rest = [rule(i, p, v)
                for i, p, v in MODULE.expected_sequence(("adminvpn0",))[1:]]
        self.assertToken(document([tampered] + rest), "RULE_GRAMMAR_UNSUPPORTED")

    def test_rule_in_unexpected_chain_fails(self):
        doc = healthy()
        doc["nftables"].append(rule("adminvpn0", 6443, "drop", chain="postrouting"))
        self.assertToken(doc, "RULE_PLACEMENT_INVALID")

    def test_future_schema_version_fails(self):
        self.assertToken(document([], schema_version=2), "SCHEMA_VERSION_UNSUPPORTED")

    def test_schema_cardinality_is_exact(self):
        missing = document([])
        missing["nftables"] = [
            item for item in missing["nftables"] if "metainfo" not in item
        ]
        duplicate = document([])
        duplicate["nftables"].insert(
            1,
            {"metainfo": {"json_schema_version": 1}},
        )
        for candidate in (missing, duplicate):
            with self.subTest(candidate=candidate):
                self.assertToken(candidate, "SCHEMA_VERSION_UNSUPPORTED")

    def test_schema_version_type_is_exact(self):
        for schema_version in (True, 1.0):
            with self.subTest(schema_version=schema_version):
                self.assertToken(
                    document([], schema_version=schema_version),
                    "SCHEMA_VERSION_UNSUPPORTED",
                )

    def test_every_failure_token_stays_in_the_closed_vocabulary(self):
        adversarial = (
            document([]),
            document([rule("adminvpn0", 22, "drop")]),
            {"nftables": [{"metainfo": {"json_schema_version": 1}}]},
            healthy(("adminvpn9",)),
        )
        for doc in adversarial:
            for token in errors(doc):
                with self.subTest(token=token):
                    self.assertIn(token, MODEL_TOKENS)


class AbsenceModeTests(unittest.TestCase):
    """The loader's pre-install proof: no owned identity, no decoy."""

    def test_schema_cardinality_and_version_are_closed(self):
        extra_top_level = {"nftables": [metainfo()], "future": {}}
        extra_metainfo = {"nftables": [metainfo()]}
        extra_metainfo["nftables"][0]["metainfo"]["future"] = "unsupported"
        empty_version = {"nftables": [metainfo()]}
        empty_version["nftables"][0]["metainfo"]["version"] = ""
        boolean_version = {"nftables": [metainfo()]}
        boolean_version["nftables"][0]["metainfo"]["version"] = True
        empty_release = {"nftables": [metainfo()]}
        empty_release["nftables"][0]["metainfo"]["release_name"] = ""
        reordered = {"nftables": [
            {"table": {"family": "ip", "name": "unrelated", "handle": 1}},
            metainfo(),
        ]}
        unsupported = (
            {"nftables": []},
            {"nftables": [metainfo(), metainfo()]},
            {"nftables": [metainfo(2)]},
            {"nftables": [metainfo(True)]},
            {"nftables": [metainfo(1.0)]},
            extra_metainfo,
            empty_version,
            boolean_version,
            empty_release,
            reordered,
        )
        for document in unsupported:
            with self.subTest(document=document):
                self.assertEqual(
                    MODULE.absence_errors(document),
                    ["SCHEMA_VERSION_UNSUPPORTED"],
                )
        self.assertEqual(
            MODULE.absence_errors(extra_top_level),
            ["RULESET_JSON_INVALID"],
        )

    def test_clean_ruleset_is_absent(self):
        doc = {"nftables": [
            metainfo(),
            {"table": {"family": "ip", "name": "unrelated", "handle": 1}},
            {"chain": {"family": "ip", "table": "unrelated", "name": "input",
                       "handle": 2, "type": "filter", "hook": "input",
                       "prio": 0, "policy": "accept"}},
        ]}
        self.assertEqual(MODULE.absence_errors(doc), [])

    def test_preexisting_owned_identity_is_reported(self):
        self.assertEqual(MODULE.absence_errors(healthy()),
                         ["PREEXISTING_OWNED_TABLE"])

    def test_decoy_chain_name_is_reported(self):
        doc = {"nftables": [
            metainfo(),
            {"chain": {"family": "ip", "table": "unrelated", "name": CHAIN,
                       "handle": 2, "type": "filter", "hook": "input",
                       "prio": 0, "policy": "accept"}},
        ]}
        self.assertEqual(MODULE.absence_errors(doc), ["CHAIN_NAME_COLLISION"])


class RawRulesetDecoderTests(unittest.TestCase):
    """Raw JSON must stay closed before Python can normalize object members."""

    def assertRawRejected(self, raw, *arguments):
        with tempfile.TemporaryDirectory() as scratch:
            ruleset = Path(scratch).resolve() / "ruleset.json"
            ruleset.write_text(raw, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(SCRIPT), "model",
                 "--ruleset", str(ruleset), *arguments],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(
            completed.stderr,
            "ingress-guard: FAIL RULESET_JSON_INVALID\n",
        )

    @staticmethod
    def duplicate_version(document):
        raw = json.dumps(document, separators=(",", ":"))
        needle = '"version":"1.0.9"'
        replacement = '"version":false,"version":"1.0.9"'
        if raw.count(needle) != 1:
            raise AssertionError("duplicate-member fixture anchor drifted")
        return raw.replace(needle, replacement, 1)

    @staticmethod
    def append_ignored_value(document, constant):
        raw = json.dumps(document, separators=(",", ":"))
        if not raw.endswith("]}"):
            raise AssertionError("non-finite fixture envelope drifted")
        return (
            raw[:-2]
            + ',{"future":{"value":'
            + constant
            + "}}]}"
        )

    def test_duplicate_object_members_fail_in_model_and_absence_modes(self):
        self.assertRawRejected(
            self.duplicate_version(healthy()),
            "--interface", "adminvpn0",
        )
        self.assertRawRejected(
            self.duplicate_version({"nftables": [metainfo()]}),
            "--expect-absent",
        )

    def test_nonstandard_numeric_constants_fail_before_foreign_objects_are_ignored(self):
        for constant in ("NaN", "Infinity", "-Infinity", "1e9999"):
            with self.subTest(mode="model", constant=constant):
                self.assertRawRejected(
                    self.append_ignored_value(healthy(), constant),
                    "--interface", "adminvpn0",
                )
            with self.subTest(mode="absence", constant=constant):
                self.assertRawRejected(
                    self.append_ignored_value(
                        {"nftables": [metainfo()]}, constant
                    ),
                    "--expect-absent",
                )

    def test_decoder_resource_failures_are_value_free(self):
        oversized_integer = self.append_ignored_value(
            healthy(), "9" * 5000
        )
        self.assertRawRejected(
            oversized_integer,
            "--interface", "adminvpn0",
        )
        deeply_nested = self.append_ignored_value(
            {"nftables": [metainfo()]}, "[" * 2000 + "0" + "]" * 2000
        )
        self.assertRawRejected(deeply_nested, "--expect-absent")


class VerifierPrivacyTests(unittest.TestCase):
    """No hostile private-looking value may reach stdout or stderr."""

    def test_hostile_interface_names_never_leak_through_the_cli(self):
        # Runtime-assembled so no private-shaped value exists at rest. The
        # name is schema-valid, so rejection comes from the model itself.
        hostile = "wg" + "casa" + "lan" + "7"
        doc = healthy((hostile,))
        doc["nftables"].append(rule(hostile, 6443, "accept"))
        with tempfile.TemporaryDirectory() as scratch:
            ruleset = Path(scratch).resolve() / "ruleset.json"
            ruleset.write_text(json.dumps(doc), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(SCRIPT), "model",
                 "--ruleset", str(ruleset), "--interface", hostile],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn(hostile, completed.stdout + completed.stderr)
        for line in completed.stderr.splitlines():
            self.assertTrue(line.startswith("ingress-guard: FAIL "), line)

    def test_interface_arguments_are_held_to_the_contract_schema(self):
        with tempfile.TemporaryDirectory() as scratch:
            ruleset = Path(scratch).resolve() / "ruleset.json"
            ruleset.write_text(json.dumps(healthy()), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(SCRIPT), "model",
                 "--ruleset", str(ruleset), "--interface", "eth0"],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("INTERFACE_ARGUMENT_INVALID", completed.stderr)


if __name__ == "__main__":
    unittest.main()
