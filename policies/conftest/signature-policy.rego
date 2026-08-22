package main

import rego.v1

# The rendered object must equal this complete data model. Object equality
# rejects duplicate semantic alternatives, extra attestors, skip lists, regular
# expressions, disabled transparency checks, and Kustomize-added bypass fields.
signature_policy_contracts := {
  "require-signed-naranjo-online": {
    "slug": "naranjo-online",
    "repository": "naranjo.online",
    "workflow": "release-publisher.yml",
    "description": "Verify the exact GitHub workflow signature and SLSA provenance bundle.",
  },
  "require-signed-lidersea-com": {
    "slug": "lidersea-com",
    "repository": "lidersea.com",
    "workflow": "release-publisher.yml",
    "description": "Verify the exact lidersea.com workflow signature and SLSA provenance bundle.",
  },
}

signature_policy_actions := {"Audit", "Enforce"}

# The two webhook failure policies a rendered signature policy may declare, and
# nothing else. `Fail` is the committed source and the enforcing install.
# `Ignore` exists for exactly one artifact: the report-only install stage
# (kubernetes/platform/admission-install/report-only), where a fail-closed
# webhook would refuse Pod creation in the site namespaces the moment the
# controller was unreachable — the failure mode that stage exists to prevent.
#
# This is an enumeration, not a relaxation: the object equality below still pins
# every other byte, so `Ignore` is only reachable on a policy that is otherwise
# byte-identical to the reviewed one. A render that pairs `Ignore` with any
# other edit is still denied.
signature_policy_failure_policies := {"Fail", "Ignore"}

# The publisher's certificate identity ends in the protected `main` branch ref,
# not a tag ref: each site's publisher is a workflow_dispatch run selected from
# protected `main`, and that ref is the only one whose creation and update those
# repositories gate with no bypass actors. This literal carries no wildcard, so
# it is strictly narrower than the `@refs/tags/v*` glob it replaces
# (ADR 0016 amendment 2026-08-22).
signature_keyless(contract) := {
  "subject": sprintf(
    "https://github.com/snaraj/%s/.github/workflows/%s@refs/heads/main",
    [contract.repository, contract.workflow],
  ),
  "issuer": "https://token.actions.githubusercontent.com",
  "rekor": {"url": "https://rekor.sigstore.dev"},
}

signature_match(contract) := {
  "any": [{
    "resources": {
      "kinds": ["Pod"],
      "namespaces": [contract.slug],
    },
  }],
}

signature_verify_image(contract) := {
  "imageReferences": [sprintf("ghcr.io/snaraj/%s@sha256:*", [contract.slug])],
  "mutateDigest": false,
  "required": true,
  "verifyDigest": true,
  "attestors": [{
    "count": 1,
    "entries": [{"keyless": signature_keyless(contract)}],
  }],
}

provenance_verify_image(contract) := {
  "imageReferences": [sprintf("ghcr.io/snaraj/%s@sha256:*", [contract.slug])],
  "type": "SigstoreBundle",
  "mutateDigest": false,
  "required": true,
  "verifyDigest": true,
  "attestations": [{
    "type": "https://slsa.dev/provenance/v1",
    "attestors": [{
      "count": 1,
      "entries": [{"keyless": signature_keyless(contract)}],
    }],
    "conditions": [{
      "all": [{
        "key": "{{ buildDefinition.buildType }}",
        "operator": "Equals",
        "value": "https://actions.github.io/buildtypes/workflow/v1",
      }],
    }],
  }],
}

expected_signature_policy(name, contract, action, failure_policy) := {
  "apiVersion": "kyverno.io/v1",
  "kind": "ClusterPolicy",
  "metadata": {
    "name": name,
    "annotations": {
      "policies.kyverno.io/category": "Software Supply Chain Security",
      "policies.kyverno.io/description": contract.description,
    },
  },
  "spec": {
    "admission": true,
    "background": false,
    "validationFailureAction": action,
    "webhookConfiguration": {
      "failurePolicy": failure_policy,
      "timeoutSeconds": 30,
    },
    "rules": [
      {
        "name": sprintf("verify-%s-signature", [contract.slug]),
        "match": signature_match(contract),
        "verifyImages": [signature_verify_image(contract)],
      },
      {
        "name": sprintf("verify-%s-provenance", [contract.slug]),
        "match": signature_match(contract),
        "verifyImages": [provenance_verify_image(contract)],
      },
    ],
  },
}

valid_signature_policy if {
  name := object.get(object.get(input, "metadata", {}), "name", "")
  contract := signature_policy_contracts[name]
  action := object.get(object.get(input, "spec", {}), "validationFailureAction", "")
  action in signature_policy_actions
  failure_policy := object.get(
    object.get(object.get(input, "spec", {}), "webhookConfiguration", {}),
    "failurePolicy",
    "",
  )
  failure_policy in signature_policy_failure_policies
  input == expected_signature_policy(name, contract, action, failure_policy)
}

deny contains msg if {
  input.kind == "ClusterPolicy"
  name := object.get(object.get(input, "metadata", {}), "name", "")
  name in object.keys(signature_policy_contracts)
  not valid_signature_policy
  msg := sprintf("signature admission policy %s has a non-canonical verification contract", [name])
}
