#!/usr/bin/env python3
"""Fail-closed validator for the API server EncryptionConfiguration."""

# Kubernetes secrets are encrypted before the first API object is stored. This
# dependency-free gate keeps the secretbox writer first and the identity provider
# only as a read fallback needed for controlled key rotation.

import argparse
import base64
import binascii
import importlib.util
import re
import sys
from pathlib import Path

try:
    from validate_kubeadm_config import ConfigSyntaxError, parse_documents
except ModuleNotFoundError:
    # Unit tests load this file by path; resolve the sibling parser explicitly.
    parser_path = Path(__file__).with_name("validate_kubeadm_config.py")
    parser_spec = importlib.util.spec_from_file_location("validate_kubeadm_config", str(parser_path))
    parser_module = importlib.util.module_from_spec(parser_spec)
    parser_spec.loader.exec_module(parser_module)
    ConfigSyntaxError = parser_module.ConfigSyntaxError
    parse_documents = parser_module.parse_documents


# _exact_keys refuses unreviewed provider fields instead of relying on API-server
# defaults that could change the encryption or decryption path.
#
# Its diagnostics name only this validator's own literal vocabulary. The file
# under inspection is the API server's EncryptionConfiguration, which carries
# the secretbox key that encrypts every Kubernetes Secret at rest, and the
# mapping this function is handed is the one holding that key. Echoing a field
# name read back out of it would copy bytes from the most sensitive file on the
# host into bootstrap output and CI logs, which is precisely the leak the
# sibling publication-history validator refuses by construction. So an expected
# field that is ABSENT is named — that name comes from the caller's literal
# argument, never from the file — while fields that are PRESENT but unreviewed
# are reported only as a count. An operator holds the file already; a count and
# the reviewed vocabulary are enough to find the offending line, and never
# enough to republish its contents.
def _exact_keys(value, expected, label, errors):
    if not isinstance(value, dict):
        errors.append("{} must be a mapping".format(label))
        return False
    reviewed = set(expected)
    actual = set(value)
    if actual != reviewed:
        missing = sorted(reviewed - actual)
        errors.append("{} must contain exactly {}; missing {}; unreviewed field count {}".format(
            label,
            ", ".join(sorted(reviewed)),
            ", ".join(missing) if missing else "none",
            len(actual - reviewed),
        ))
        return False
    return True


# validate proves the complete one-rule, two-provider contract and verifies that
# the generated secretbox key is canonical base64 for exactly 32 random bytes.
def validate(text):
    errors = []
    if re.search(r"(?:REPLACE_|UNRESOLVED)", text, flags=re.IGNORECASE):
        errors.append("replacement sentinel remains")
    try:
        documents = parse_documents(text)
    except ConfigSyntaxError as error:
        return errors + [str(error)]

    if set(documents) != {"EncryptionConfiguration"}:
        errors.append("configuration must contain exactly one EncryptionConfiguration document")
        return errors

    root = documents["EncryptionConfiguration"]
    _exact_keys(root, {"apiVersion", "kind", "resources"}, "EncryptionConfiguration", errors)
    if root.get("apiVersion") != "apiserver.config.k8s.io/v1":
        errors.append("EncryptionConfiguration.apiVersion must be apiserver.config.k8s.io/v1")

    resources = root.get("resources")
    if not isinstance(resources, list) or len(resources) != 1 or not isinstance(resources[0], dict):
        errors.append("resources must contain exactly one resource rule")
        return errors

    rule = resources[0]
    _exact_keys(rule, {"resources", "providers"}, "resources[0]", errors)
    if rule.get("resources") != ["secrets"]:
        errors.append("resources[0].resources must be exactly [secrets]")

    providers = rule.get("providers")
    if not isinstance(providers, list) or len(providers) != 2:
        errors.append("providers must contain exactly secretbox first and identity second")
        return errors
    if not all(isinstance(provider, dict) for provider in providers):
        errors.append("each provider must be a mapping")
        return errors
    if set(providers[0]) != {"secretbox"} or set(providers[1]) != {"identity"}:
        errors.append("providers must contain exactly secretbox first and identity second")
        return errors
    if providers[1].get("identity") != "{}":
        errors.append("identity fallback must be the empty mapping and appear second")

    secretbox = providers[0].get("secretbox")
    if not _exact_keys(secretbox, {"keys"}, "secretbox", errors):
        return errors
    keys = secretbox.get("keys")
    if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
        errors.append("secretbox.keys must contain exactly one key")
        return errors
    key = keys[0]
    _exact_keys(key, {"name", "secret"}, "secretbox.keys[0]", errors)
    name = key.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"key-[0-9]{4}-[0-9]{2}", name):
        errors.append("secretbox key name must use key-YYYY-MM")
    secret = key.get("secret")
    if not isinstance(secret, str):
        errors.append("secretbox key must be one base64 scalar")
    else:
        try:
            decoded = base64.b64decode(secret, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != secret:
            errors.append("secretbox key must be canonical base64 encoding exactly 32 bytes")
    return errors


# main makes the validator usable both from the kubeadm installer and unit tests,
# with failures emitted in a consistent machine-readable form.
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    args = parser.parse_args(argv)
    try:
        text = args.config.read_text(encoding="utf-8")
    except OSError as error:
        print("FAIL unable to read encryption config: {}".format(error), file=sys.stderr)
        return 1
    errors = validate(text)
    if errors:
        for error in errors:
            print("FAIL " + error, file=sys.stderr)
        return 1
    print("PASS encryption config is exact: secretbox first, identity read fallback second")
    return 0


if __name__ == "__main__":
    sys.exit(main())
