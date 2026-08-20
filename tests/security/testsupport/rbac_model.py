"""A model of Kubernetes RBAC, and of what this repository asks Flux to apply.

WHY THIS EXISTS
---------------

Removing ``cluster-admin`` from the Flux reconcilers converts one failure mode
into another. With the broad binding every reconciliation succeeded, including
the ones nobody reviewed. Without it, a permission this repository forgot to
grant does not fail in review or in CI — it fails at reconcile time, on the
cluster, as a Kustomization that stops halfway with an RBAC denial in a status
condition nobody is watching. That is a 3am failure produced by a change whose
whole purpose was safety.

So the narrowing ships with a proof: every object the reviewed desired state
would apply is enumerated from the manifests themselves, mapped to the
``(subject, verb, apiGroup, resource, namespace)`` tuples the API server would
authorize, and evaluated against the committed Roles and RoleBindings by a model
of the RBAC authorizer. A missing grant is a failing test in `make check-fast`,
before anything reaches a cluster.

WHAT IS AND IS NOT PROVEN
-------------------------

Proven: the committed authorization permits every request the committed desired
state implies under the impersonation model Flux documents, and denies an
enumerated set of requests it must never permit.

NOT proven: that a running API server agrees. No apiserver, no controller, and
no admission plugin executes here. Three things are modelled rather than
observed and are named as such at their definitions: the verb set a Flux apply
issues (``APPLY_VERBS``), the kinds each Helm chart renders (``SITE_CHART_KINDS``
for charts that live in the site repositories), and the kind-to-resource mapping
(``KIND_RESOURCES``). The live half of the proof is
``bootstrap/flux/bootstrap.sh --verify`` plus the ``kubectl auth can-i`` sweep in
``docs/runbooks/flux-rbac-narrowing.md``; this module is what makes that sweep
short enough to trust and repeatable enough to run.

This module is support code: unittest discovery only collects ``test_*.py``, and
the coverage gate measures ``scripts/`` alone, so nothing here enters any
coverage denominator.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple


REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# A deliberately small YAML reader
# ---------------------------------------------------------------------------
#
# The repository's Python gates run with the standard library only, so there is
# no YAML parser to import. This reader accepts exactly the block-style subset
# the reviewed manifests are written in and RAISES on anything else — anchors,
# aliases, merge keys, tabs, flow mappings. Failing loudly on an unsupported
# construct is the point: a silently mis-parsed RBAC rule would turn this proof
# into decoration.


class YamlSubsetError(ValueError):
    """Raised when a manifest uses a construct this reader will not guess at."""


def _indent_of(line):
    """Columns of leading spaces, computed rather than matched.

    A regex here would return an Optional the caller has to unwrap, and this
    reader must never fail by dereferencing None: an input it cannot parse has
    to raise ``YamlSubsetError`` with the offending line, because a crash inside
    the sufficiency proof would read as "no permission gap found".
    """

    return len(line) - len(line.lstrip(" "))


def _strip_comment(line):
    """Remove a trailing comment, honouring quoted scalars."""

    quote = ""
    for index, character in enumerate(line):
        if quote:
            if character == quote:
                quote = ""
            continue
        if character in "\"'":
            quote = character
            continue
        if character == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index].rstrip()
    return line.rstrip()


def _scalar(value):
    """Convert a plain or quoted YAML scalar to a Python value."""

    text = value.strip()
    if not text:
        return ""
    if text[0] in "\"'" and len(text) >= 2 and text[-1] == text[0]:
        return text[1:-1]
    if text in {"true", "True"}:
        return True
    if text in {"false", "False"}:
        return False
    if text in {"null", "~"}:
        return None
    if text[0] in "&*<":
        raise YamlSubsetError("anchors, aliases and merge keys are not supported: " + text)
    if text == "{}":
        # `podSelector: {}` — an empty flow mapping is the idiomatic
        # select-everything in a NetworkPolicy, so it is the one flow mapping
        # this reader accepts.
        return {}
    if text[0] == "{":
        raise YamlSubsetError("flow mappings are not supported: " + text)
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def _flow_sequence(value):
    """Parse ``[a, b, 'c']`` into a list of scalars."""

    inner = value.strip()[1:-1].strip()
    if not inner:
        return []
    return [_scalar(item) for item in inner.split(",")]


def _value(raw):
    text = raw.strip()
    if text.startswith("["):
        if not text.endswith("]"):
            raise YamlSubsetError("multi-line flow sequences are not supported: " + text)
        return _flow_sequence(text)
    return _scalar(text)


class _Reader:
    def __init__(self, lines):
        self.lines = lines
        self.position = 0

    def peek(self):
        """The next significant line as ``(indent, text)``, or ``None`` at end.

        One optional return, unwrapped once per call site, instead of a pair of
        Optionals that every caller has to remember to check twice.
        """

        while self.position < len(self.lines):
            raw = self.lines[self.position]
            if "\t" in raw:
                raise YamlSubsetError("tab indentation is not supported")
            stripped = _strip_comment(raw)
            if not stripped.strip():
                self.position += 1
                continue
            return _indent_of(stripped), stripped.strip()
        return None

    def parse_block(self, indent):
        entry = self.peek()
        if entry is None:
            return None
        current, text = entry
        if current < indent:
            return None
        if text.startswith("- "):
            return self._parse_sequence(current)
        return self._parse_mapping(current)

    def _parse_sequence(self, indent):
        items = []
        while True:
            entry = self.peek()
            if entry is None:
                break
            current, text = entry
            if current < indent or not text.startswith("- "):
                break
            if current > indent:
                raise YamlSubsetError("inconsistent sequence indentation: " + text)
            body = text[2:]
            self.position += 1
            if ":" in body and not body.startswith("["):
                # ``- key: value`` opens a mapping whose remaining keys are
                # indented to the position of the key itself.
                key, _, remainder = body.partition(":")
                item = {}
                item.update(self._entry(key.strip(), remainder, indent + 2))
                nested = self._parse_mapping(indent + 2, existing=item)
                items.append(nested)
            else:
                items.append(_value(body))
        return items

    def _entry(self, key, remainder, key_indent):
        """Parse one ``key: …`` entry, including whatever block follows it."""

        remainder = remainder.strip()
        if remainder in {"|", "|-", ">", ">-"}:
            return {key: self._block_scalar()}
        if remainder:
            return {key: _value(remainder)}
        entry = self.peek()
        if entry is None:
            return {key: {}}
        current, text = entry
        # A sequence under a mapping key may be indented to the key's own column
        # — the style the generated Flux export uses — or deeper, the style the
        # reviewed manifests use. Both are ordinary YAML and both appear here.
        if text.startswith("- ") and current >= key_indent:
            return {key: self._parse_sequence(current)}
        if current > key_indent:
            return {key: self._parse_mapping(current)}
        return {key: {}}

    def _block_scalar(self):
        collected = []
        indent = 0
        started = False
        while self.position < len(self.lines):
            raw = self.lines[self.position].rstrip("\n")
            if raw.strip():
                current = _indent_of(raw)
                if not started:
                    indent = current
                    started = True
                elif current < indent:
                    break
            collected.append(raw[indent:] if len(raw) >= indent else raw.strip())
            self.position += 1
        return "\n".join(collected).rstrip("\n") + "\n"

    def _parse_mapping(self, indent, existing=None):
        mapping = existing if existing is not None else {}
        while True:
            entry = self.peek()
            if entry is None:
                break
            current, text = entry
            if current < indent:
                break
            if current > indent:
                raise YamlSubsetError("inconsistent mapping indentation: " + text)
            if text.startswith("- "):
                break
            if ":" not in text:
                raise YamlSubsetError("unsupported line: " + text)
            key, _, remainder = text.partition(":")
            self.position += 1
            mapping.update(self._entry(key.strip(), remainder, indent))
        return mapping


def parse_documents(text):
    """Parse a multi-document manifest into plain Python structures."""

    documents = []
    for chunk in re.split(r"(?m)^---\s*$", text):
        lines = chunk.splitlines()
        reader = _Reader(lines)
        parsed = reader.parse_block(0)
        if isinstance(parsed, dict) and parsed:
            documents.append(parsed)
        elif parsed:
            raise YamlSubsetError("top-level sequences are not supported")
    return documents


def load_documents(path):
    return parse_documents(Path(path).read_text(encoding="utf-8"))


RBAC_KINDS = ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding")


def load_rbac_documents(path):
    """Parse only the RBAC documents out of a manifest.

    ``gotk-components.yaml`` is a 5000-line generated export dominated by
    CustomResourceDefinitions whose OpenAPI schemas use YAML this reader
    deliberately refuses. The RBAC objects inside it are plain, so they are
    sliced out by kind before parsing and the rest is never read.
    """

    text = Path(path).read_text(encoding="utf-8")
    documents = []
    for chunk in re.split(r"(?m)^---\s*$", text):
        match = re.search(r"(?m)^kind:\s*(\S+)\s*$", chunk)
        if match is None or match.group(1) not in RBAC_KINDS:
            continue
        documents.extend(parse_documents(chunk))
    return documents


# The narrowing patches, in the order the install root applies them. Each is a
# Kustomize strategic-merge patch against the generated export.
FLUX_RBAC_PATCH_FILES = (
    "kubernetes/flux-system/controllers/patches/cluster-reconciler.yaml",
    "kubernetes/flux-system/controllers/patches/crd-controller-role.yaml",
    "kubernetes/flux-system/controllers/patches/crd-controller-binding.yaml",
)

# Authored RBAC that is a RESOURCE of the install root rather than a patch of
# the generated export: the six per-controller objects (issue #98). They live in
# the install root because the patch above removes the authority they replace in
# the same transaction — see `controller_root_rbac`.
FLUX_CONTROLLER_ROOT_RBAC_FILES = (
    "kubernetes/flux-system/controllers/per-controller-rbac.yaml",
)


def _identity(document):
    metadata = document.get("metadata") or {}
    return document.get("kind"), metadata.get("namespace"), metadata.get("name")


def apply_patches(base, patches):
    """Compose generated RBAC with the reviewed patches.

    Only the two Kustomize behaviours this repository relies on are modelled:
    ``$patch: delete`` removes the object, and any other patch replaces the
    top-level fields it names. Both were verified against the pinned Kustomize
    build, and ``test_flux_rbac_contract`` re-verifies the composition against
    real ``kustomize build`` output whenever the pinned binary is available, so
    a divergence between this model and the renderer is itself a failure.
    """

    composed = {_identity(document): dict(document) for document in base}
    for patch in patches:
        key = _identity(patch)
        if patch.get("$patch") == "delete":
            composed.pop(key, None)
            continue
        if key not in composed:
            raise AssertionError("patch targets an object the export does not define: %r" % (key,))
        target = composed[key]
        for field, value in patch.items():
            if field in {"apiVersion", "kind", "metadata", "$patch"}:
                continue
            target[field] = value
    return list(composed.values())


def controller_root_rbac(root=REPO_ROOT):
    """The RBAC the INSTALLER alone creates: the `controllers` root, rendered.

    Modelled separately from `effective_flux_rbac` because the two are applied
    by different actors at different times. `scripts/install-flux-controllers.sh`
    applies THIS root and nothing else; `access.yaml` arrives later, reconciled
    by Flux from `./kubernetes/reconciliation`, and cannot help a controller that
    has to start an informer before Flux is running at all.

    That distinction is not academic. The narrowing patch strips every Flux API
    group from the shared `crd-controller-flux-system` ClusterRole, so while the
    six per-controller replacements sat in access.yaml this composition denied
    all fourteen registered-kind list/watch probes and a fresh install could
    never reach readiness. The replacements are part of this root now, and
    `FluxRbacControllerRootSufficiencyTests` builds an authorizer from exactly
    this function so that regression is caught by name.
    """

    root = Path(root)
    base = load_rbac_documents(root / "kubernetes/flux-system/controllers/gotk-components.yaml")
    patches = []
    for relative in FLUX_RBAC_PATCH_FILES:
        patches.extend(load_documents(root / relative))
    documents = apply_patches(base, patches)
    for relative in FLUX_CONTROLLER_ROOT_RBAC_FILES:
        documents.extend(load_documents(root / relative))
    return documents


def effective_flux_rbac(root=REPO_ROOT):
    """The RBAC the cluster would hold: the install root, then access.yaml."""

    documents = controller_root_rbac(root)
    documents.extend(load_documents(Path(root) / "kubernetes/flux-system/access.yaml"))
    return documents


# ---------------------------------------------------------------------------
# The authorizer
# ---------------------------------------------------------------------------


class Subject(tuple):
    """A ServiceAccount identity, written the way RBAC subjects are."""

    __slots__ = ()

    def __new__(cls, namespace, name):
        return super().__new__(cls, (namespace, name))

    @property
    def namespace(self):
        return self[0]

    @property
    def name(self):
        return self[1]

    def __str__(self):
        return "system:serviceaccount:{}:{}".format(*self)


def _matches(values, wanted):
    return "*" in values or wanted in values


class Authorizer:
    """Evaluate ``(subject, verb, group, resource, namespace, name)`` requests.

    The semantics modelled are the ones that matter to this change:

    * a ClusterRoleBinding applies its ClusterRole in every namespace and at
      cluster scope;
    * a RoleBinding applies its role — Role or ClusterRole — only inside the
      binding's own namespace, never at cluster scope;
    * ``resourceNames`` restricts a rule to named objects, and a request that
      carries no object name (``list``, ``watch``, ``create``) therefore cannot
      be authorized by a rule that sets it. That asymmetry is why the SOPS key
      read is granted namespace-wide instead of by name.
    """

    def __init__(self):
        self.roles = {}
        self.cluster_roles = {}
        self.bindings = []
        self.cluster_bindings = []

    @classmethod
    def from_documents(cls, documents):
        authorizer = cls()
        for document in documents:
            kind = document.get("kind")
            metadata = document.get("metadata") or {}
            name = metadata.get("name")
            namespace = metadata.get("namespace")
            if kind == "Role":
                authorizer.roles[(namespace, name)] = document.get("rules") or []
            elif kind == "ClusterRole":
                authorizer.cluster_roles[name] = document.get("rules") or []
            elif kind == "RoleBinding":
                authorizer.bindings.append((namespace, document))
            elif kind == "ClusterRoleBinding":
                authorizer.cluster_bindings.append((None, document))
        authorizer.require_resolvable_role_refs()
        return authorizer

    @classmethod
    def from_paths(cls, paths):
        documents = []
        for path in paths:
            documents.extend(load_documents(path))
        return cls.from_documents(documents)

    def require_resolvable_role_refs(self):
        """Refuse a binding whose role is not in the reviewed document set.

        Without this the model reads an unresolvable ``roleRef`` as granting
        nothing — a false green in the worst direction. A binding to a
        Kubernetes BUILT-IN role (``cluster-admin``, ``admin``, ``edit``, any
        ``system:*``) is never among the parsed documents, so the model would
        report every request denied while the cluster granted them all; today
        ``cluster-admin`` is caught only by a name-string check, never by this
        authorizer. There is deliberately NO allowlist of built-ins: this
        repository binds its Flux accounts only to roles it defines and reviews,
        so any other reference is itself the finding, and naming an approved
        built-in here would reopen the hole.
        """

        unresolvable = []
        for binding_namespace, binding in self.bindings + self.cluster_bindings:
            role_ref = binding.get("roleRef") or {}
            name = role_ref.get("name")
            if role_ref.get("kind") == "ClusterRole":
                if name not in self.cluster_roles:
                    unresolvable.append((binding, "ClusterRole", name))
            elif (binding_namespace, name) not in self.roles:
                unresolvable.append((binding, "Role", name))
        if unresolvable:
            raise AssertionError(
                "binding(s) reference a role outside the reviewed set, so this "
                "model can no longer see the authority they grant: "
                + ", ".join(
                    "{} -> {}/{}".format(
                        (binding.get("metadata") or {}).get("name"), kind, name
                    )
                    for binding, kind, name in unresolvable
                )
            )

    def _rules_for(self, binding, binding_namespace):
        role_ref = binding.get("roleRef") or {}
        if role_ref.get("kind") == "ClusterRole":
            return self.cluster_roles[role_ref.get("name")]
        return self.roles[(binding_namespace, role_ref.get("name"))]

    def _binds(self, binding, subject):
        """Whether ``binding`` reaches ``subject`` by ANY subject form.

        A ServiceAccount is reachable three ways, and a model that understood
        only the first would report "denied" for authority the cluster grants:
        as a ``ServiceAccount`` subject, as the ``User``
        ``system:serviceaccount:<ns>:<name>``, or through a ``Group`` —
        ``system:serviceaccounts`` (every account in the cluster),
        ``system:serviceaccounts:<ns>`` (every account in one namespace), or
        ``system:authenticated``. The live-state verifier in
        ``bootstrap/flux/bootstrap.sh`` refuses group-shaped bindings that reach
        a protected account for exactly this reason; without this the model was
        strictly weaker than the verifier it claims to mirror.
        """

        namespace, name = tuple(subject)
        groups = {
            "system:authenticated",
            "system:serviceaccounts",
            "system:serviceaccounts:" + str(namespace),
        }
        for entry in binding.get("subjects") or []:
            kind = entry.get("kind")
            if kind == "ServiceAccount":
                if (entry.get("namespace"), entry.get("name")) == (namespace, name):
                    return True
            elif kind == "User":
                if entry.get("name") == "system:serviceaccount:{}:{}".format(namespace, name):
                    return True
            elif kind == "Group":
                if entry.get("name") in groups:
                    return True
        return False

    def rules_for_subject(self, subject, namespace):
        """Every rule that applies to ``subject`` in ``namespace``.

        ``namespace=None`` means cluster scope, where only ClusterRoleBindings
        contribute.
        """

        collected = []
        for _, binding in self.cluster_bindings:
            if self._binds(binding, subject):
                collected.extend(self._rules_for(binding, None))
        if namespace is not None:
            for binding_namespace, binding in self.bindings:
                if binding_namespace == namespace and self._binds(binding, subject):
                    collected.extend(self._rules_for(binding, binding_namespace))
        return collected

    def allows_non_resource(self, subject, verb, url):
        """Authorize a non-resource URL request, which only a ClusterRole can."""

        for rule in self.rules_for_subject(subject, None):
            if not _matches(rule.get("verbs") or [], verb):
                continue
            if _matches(rule.get("nonResourceURLs") or [], url):
                return True
        return False

    def allows(self, subject, verb, group, resource, namespace=None, name=None):
        for rule in self.rules_for_subject(subject, namespace):
            if not _matches(rule.get("verbs") or [], verb):
                continue
            # A rule carrying nonResourceURLs is a non-resource rule, answered
            # by allows_non_resource instead. Kubernetes ignores
            # apiGroups/resources on such a rule, so a hand-written rule setting
            # BOTH would authorize a resource request this model reports as
            # denied. That divergence is in the SAFE direction (the model is
            # stricter than the cluster), is unreachable in this repository
            # because no rule here mixes the two, and is noted so a future
            # reader does not mistake it for a bug.
            if "nonResourceURLs" in rule:
                continue
            if not _matches(rule.get("apiGroups") or [], group):
                continue
            if not _matches(rule.get("resources") or [], resource):
                continue
            resource_names = rule.get("resourceNames")
            if resource_names and (name is None or name not in resource_names):
                continue
            return True
        return False


# ---------------------------------------------------------------------------
# What the reviewed desired state asks for
# ---------------------------------------------------------------------------

# MODEL. The verbs a Flux apply issues against an object it manages: it reads
# the live object, creates it when absent, patches it when present, and — with
# ``prune: true`` — deletes it when it leaves the source. ``watch`` is
# deliberately not required: Flux polls managed objects, and requiring a verb the
# reconciler may not use would produce false failures in the only direction that
# matters (a red build for a permission nothing needs).
APPLY_VERBS = ("get", "list", "create", "update", "patch", "delete")

# MODEL. Kubernetes kind -> (apiGroup, resource plural, namespaced). Only the
# kinds this repository's reviewed desired state actually contains are listed;
# an unlisted kind raises rather than being assumed harmless.
KIND_RESOURCES = {
    "Bucket": ("source.toolkit.fluxcd.io", "buckets", True),
    "ConfigMap": ("", "configmaps", True),
    "Deployment": ("apps", "deployments", True),
    "GitRepository": ("source.toolkit.fluxcd.io", "gitrepositories", True),
    "HelmChart": ("source.toolkit.fluxcd.io", "helmcharts", True),
    "HelmRepository": ("source.toolkit.fluxcd.io", "helmrepositories", True),
    "HelmRelease": ("helm.toolkit.fluxcd.io", "helmreleases", True),
    "Kustomization": ("kustomize.toolkit.fluxcd.io", "kustomizations", True),
    "LimitRange": ("", "limitranges", True),
    "Namespace": ("", "namespaces", False),
    "NetworkPolicy": ("networking.k8s.io", "networkpolicies", True),
    "OCIRepository": ("source.toolkit.fluxcd.io", "ocirepositories", True),
    "ResourceQuota": ("", "resourcequotas", True),
    "Secret": ("", "secrets", True),
    "Service": ("", "services", True),
    "ServiceAccount": ("", "serviceaccounts", True),
    "ClusterPolicy": ("kyverno.io", "clusterpolicies", False),
    "ValidatingWebhookConfiguration": (
        "admissionregistration.k8s.io", "validatingwebhookconfigurations", False,
    ),
}

# MODEL, and the one input that cannot be derived from this repository: each
# site's Helm chart is built, signed, and published by that site's own
# repository (AGENTS.md safety invariant 11), so the kinds it renders are
# declared here per site. Each list is the chart's template set, and the two
# sites are declared separately because their identity tuples never couple.
#
# The key is the owner's ``(kind, name)`` pair, never the bare name: a
# Kustomization and a HelmRelease share a name for both sites, so a bare-name
# table can be satisfied by the wrong object — the exact defect that let a
# declared authorization gap survive a mutation earlier in this change.
SITE_CHART_KINDS = {
    ("HelmRelease", "naranjo-online"): (
        "Deployment", "Service", "ServiceAccount", "NetworkPolicy",
    ),
    ("HelmRelease", "lidersea-com"): (
        "Deployment", "Service", "ServiceAccount", "NetworkPolicy",
    ),
}

# Helm keeps one release-state Secret per revision in the release namespace, so
# every HelmRelease implies Secret authority for the account it runs as.
HELM_STORAGE_KIND = "Secret"

FLUX_SYSTEM = "flux-system"

# Source objects. A source is read TWICE under two DIFFERENT identities, which
# is why both halves are derived: the impersonated reconciler applies the object
# from Git, and the controllers then read it under their OWN identity to resolve
# an artifact.
SOURCE_KINDS = ("GitRepository", "OCIRepository", "HelmRepository", "Bucket", "HelmChart")

# MODEL, and load-bearing: a reconciler resolves `spec.sourceRef` /
# `spec.chartRef` through its own API client BEFORE the impersonation config is
# built, so reading the source is the CONTROLLER's authority and never the
# impersonated account's. It is also the first thing every reconciliation does —
# without it the root Kustomization cannot read the GitRepository it syncs from
# and nothing reconciles at all.
SOURCE_READ_VERBS = ("get", "list", "watch")

# What source-controller does to the sources it owns, under its own identity.
SOURCE_OWNER_VERBS = ("get", "list", "watch", "update", "patch")

# MODEL. Cluster metadata every controller reads under its own identity, each
# row carrying the reason it cannot be dropped. These are exactly the grants
# that stay cluster-scoped in the narrowed ClusterRole, so each is emitted as a
# requirement rather than defended only in prose: deleting any row from the
# ClusterRole must fail the suite.
CONTROLLER_BASELINE_GRANTS = (
    ("", "namespaces", ("get", "list", "watch"),
     "health evaluation and pruning read namespace metadata"),
    ("", "serviceaccounts", ("get", "list", "watch"),
     "a controller resolves the account it is about to impersonate"),
    ("", "configmaps", ("get", "list", "watch"),
     "postBuild.substituteFrom and Helm valuesFrom read ConfigMaps"),
)

# MODEL, declared rather than derived from the desired state, and required of
# every installed controller inside its OWN namespace. Nothing a reconciliation
# applies implies these, so a desired-state derivation cannot reach them — but
# they are what the controller process itself does at runtime, and a narrowing
# that dropped them would pass a desired-state-only proof and then fail live.
# Each row is asserted rather than argued: deleting the matching rule from
# `kubernetes/flux-system/access.yaml` (and from the bootstrap mirror) turns the
# suite red.
#
# Direction of the trade: requiring a grant the controller might not exercise
# costs a red build for an unnecessary permission, while NOT requiring one it
# does exercise costs a crashloop on a cluster nobody is watching. The peer
# review of this change asked for the strict side, and this is it. The live
# confirmation is the `kubectl auth can-i` sweep in the runbook, which carries a
# row for each.
CONTROLLER_RUNTIME_GRANTS = (
    ("", "configmaps", ("create", "update", "patch", "delete"),
     "controller-runtime owns ConfigMaps in its own namespace; the generated "
     "export grants the write half cluster-wide and this change confines it to "
     "flux-system rather than removing it"),
    ("", "configmaps/status", ("get", "update", "patch"),
     "the status subresource of the same controller-owned ConfigMaps"),
)

# DERIVED, from the pinned controller Deployments themselves: a Deployment that
# carries `--enable-leader-election` takes a Lease in its own namespace before it
# reconciles anything, so losing the Lease grant is a startup crashloop and zero
# reconciliation — the loudest possible failure, and one no desired-state
# enumeration would ever produce. Reading the flag out of the export means the
# requirement follows the install: remove the flag and the requirement goes away,
# remove the grant while the flag stands and the suite fails.
#
# The verbs are the ones client-go's LeaseLock issues (Get, Create, Update). The
# export grants more; the surplus is declared slack in the narrowness proof
# rather than silently absorbed here.
LEADER_ELECTION_FLAG = "--enable-leader-election"
LEADER_ELECTION_VERBS = ("get", "create", "update")

# MODEL. The custom resources each controller REGISTERS a reconciler for at the
# pinned version — not the objects that happen to exist in today's desired
# state. A controller starts one informer per registered kind at startup and
# exits if it cannot list/watch it, so "this repository declares no Bucket" is
# not evidence that the Bucket grant is unused; it is only evidence that no
# Bucket is reconciled. Deriving from this table instead of from the object
# inventory is what makes deleting a source grant fail here.
REGISTERED_CONTROLLERS = {
    "source-controller": ("Bucket", "GitRepository", "HelmChart", "HelmRepository", "OCIRepository"),
    "kustomize-controller": ("Kustomization",),
    "helm-controller": ("HelmRelease",),
}

# With this flag every registered informer is a CLUSTER-wide list/watch, which
# no Role can satisfy — the reason the own-resource grants stay in a ClusterRole
# after everything else moved to namespaced Roles.
WATCH_ALL_NAMESPACES_FLAG = "--watch-all-namespaces=true"

# What a controller does to a custom resource it owns: reconcile it, own its
# status, and manage its finalizer. Finalizer access is only consulted when the
# API server runs OwnerReferencesPermissionEnforcement, but a missing grant
# there produces a stuck deletion rather than a clear denial.
OWNED_RESOURCE_VERBS = ("get", "list", "watch", "update", "patch")
OWNED_STATUS_VERBS = ("get", "patch", "update")
OWNED_FINALIZER_VERBS = ("update",)

# Event reporting is namespaced in effect — an Event is written in the namespace
# of the object it describes — so it is required in every reconciled namespace.
EVENT_VERBS = ("create", "patch")

# The API-server liveness probe: the one non-resource URL the controllers use,
# and the only grant here that a Role could not express.
LIVENESS_URL = "/livez/ping"

# MODEL. Kinds whose readiness is evaluated by walking down to the Pods they
# create. A `wait: true` Kustomization and a HelmRelease that has not disabled
# Helm's wait both read that chain back under the IMPERSONATED identity, so the
# authority belongs to the reconciler account, not to the controller.
WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")
READ_BACK_RESOURCES = (("apps", "replicasets"), ("", "pods"))
READ_BACK_VERBS = ("get", "list")


class FluxResources(NamedTuple):
    """The reviewed desired state's Flux custom resources, by kind.

    A NamedTuple rather than a bare tuple on purpose: this module is the
    artifact the unsuspend gate rests on, and widening a plain tuple return
    silently breaks callers at unpack time — a crash where a missing-permission
    REPORT belongs, which is the precise false-green class this whole proof
    exists to eliminate.
    """

    kustomizations: list
    helm_releases: list
    sources: list


class DerivedRequirements(NamedTuple):
    """What the desired state needs, split by whose identity performs it."""

    #: Requests made by an impersonated per-tenant reconciler account.
    applied: list
    #: Requests a controller makes under its own ServiceAccount.
    controller: list
    #: Non-resource URL requests, which only a ClusterRole can authorize.
    non_resource: list


class NonResourceRequirement(NamedTuple):
    """One non-resource URL authorization the controllers depend on."""

    subject: Subject
    verb: str
    url: str
    reason: str

    def describe(self):
        return "{} may {} {} ({})".format(self.subject, self.verb, self.url, self.reason)


class Requirement(tuple):
    """One authorization the reviewed desired state depends on."""

    __slots__ = ()

    def __new__(cls, subject, verb, group, resource, namespace, name, owner, reason):
        return super().__new__(
            cls, (subject, verb, group, resource, namespace, name, owner, reason)
        )

    subject = property(lambda self: self[0])
    verb = property(lambda self: self[1])
    group = property(lambda self: self[2])
    resource = property(lambda self: self[3])
    namespace = property(lambda self: self[4])
    name = property(lambda self: self[5])
    #: The Flux custom resource whose reconciliation needs this authorization,
    #: as a ``(kind, name)`` pair. The kind is load-bearing: a Kustomization and
    #: a HelmRelease may share a name (both sites do), and each is suspended by
    #: its OWN spec.suspend — so a bare name cannot say which object a declared
    #: authorization gap belongs to, and unsuspending one of the pair would not
    #: be noticed.
    owner = property(lambda self: self[6])
    reason = property(lambda self: self[7])

    def describe(self):
        scope = self.namespace or "cluster scope"
        target = "{}/{}".format(self.group or "core", self.resource)
        named = "" if self.name is None else " named " + self.name
        return "{} may {} {}{} in {} ({})".format(
            self.subject, self.verb, target, named, scope, self.reason
        )


def _kind_tuple(kind):
    if kind not in KIND_RESOURCES:
        raise AssertionError(
            "unmodelled kind {!r}: add it to KIND_RESOURCES with its apiGroup and "
            "resource, and re-derive the permissions it needs".format(kind)
        )
    return KIND_RESOURCES[kind]


# Top-level Kustomize keys this enumeration understands. Anything else can put
# an object into the cluster that `resources:` never names — `configMapGenerator`
# and `secretGenerator` synthesize objects outright, `components` pull in another
# root, `namespace`/`namePrefix` retarget or rename what is applied — so an
# unreviewed key is REFUSED rather than skipped. Skipping it would under-count
# the desired state, and under-counting is exactly how a sufficiency proof lies.
ALLOWED_KUSTOMIZATION_KEYS = {"apiVersion", "kind", "resources"}


def _kustomization_paths(root, relative):
    """Every manifest file a Kustomize root pulls in, recursively."""

    base = root / relative
    index = base / "kustomization.yaml"
    documents = load_documents(index)
    if not documents:
        # An empty or unreadable Kustomize root would silently contribute zero
        # objects, which is indistinguishable from "everything is authorized".
        raise AssertionError("no Kustomize root parsed at " + str(index))
    unreviewed = sorted(set(documents[0]) - ALLOWED_KUSTOMIZATION_KEYS)
    if unreviewed:
        raise AssertionError(
            "Kustomize root {} uses key(s) this enumeration cannot follow: {}. "
            "Teach objects_applied_by to expand them, or the objects they add "
            "reach the cluster with no derived permission at all.".format(
                index, ", ".join(unreviewed)
            )
        )
    resources = documents[0].get("resources") or []
    files = []
    for entry in resources:
        if not isinstance(entry, str):
            # A remote base (`- https://github.com/…?ref=v1`) parses as a mapping
            # here, and used to reach `Path / dict` and die as a TypeError — fail
            # closed, but with a traceback nobody can act on. It is refused by
            # name instead: objects from outside the reviewed tree would be
            # applied with no derived permission at all. kustomize-controller
            # additionally runs with `--no-remote-bases=true`, so this is the
            # enumeration half of a refusal the cluster also makes.
            raise AssertionError(
                "Kustomize root {} lists a resource this enumeration cannot "
                "follow: {!r}. Remote bases are refused, not resolved.".format(
                    index, entry
                )
            )
        target = (base / entry).resolve()
        if target.is_dir():
            files.extend(_kustomization_paths(root, target.relative_to(root)))
        else:
            files.append(target)
    return files


def objects_applied_by(root, relative):
    """Return ``(kind, namespace, name)`` for every object a path applies."""

    applied = []
    for path in _kustomization_paths(root, relative):
        for document in load_documents(path):
            metadata = document.get("metadata") or {}
            applied.append(
                (document.get("kind"), metadata.get("namespace"), metadata.get("name"))
            )
    if not applied:
        # A reconciled path that applies nothing needs no permission, so it
        # would satisfy every sufficiency assertion below while proving nothing
        # about the path it was supposed to cover. `resources: []` is the
        # concrete way this happens.
        raise AssertionError("no objects enumerated for reconciled path " + str(relative))
    return applied


def chart_kinds(root, relative):
    """Kinds a chart in THIS repository renders.

    Helm templates are not YAML until Helm has run, so the kinds are read the
    way the repository's other gates read them: the ``kind:`` field of each
    template document.

    ``rglob`` rather than ``glob``: Helm renders every template under
    ``templates/`` at any depth, so a single-level glob made the same file
    invisible purely by living in a subdirectory — `templates/cronjob.yaml`
    raised "unmodelled kind" while `templates/jobs/cronjob.yaml` was silently
    dropped from the derivation.
    """

    kinds = []
    for path in sorted((root / relative / "templates").rglob("*.yaml")):
        kinds.extend(re.findall(r"(?m)^kind:\s*(\S+)\s*$", path.read_text(encoding="utf-8")))
    return kinds


# The reviewed controller patches are JSON patches that only APPEND arguments
# (`op: add` on `.../args/-`). That is what makes deriving leader election from
# the generated export sound — a patch that could REPLACE the argument list could
# drop `--enable-leader-election` while this reader still saw it — so any other
# shape of args patch is refused rather than reasoned about.
CONTROLLER_DEPLOYMENT_PATCH_FILES = (
    "kubernetes/flux-system/controllers/patches/source-controller.yaml",
    "kubernetes/flux-system/controllers/patches/kustomize-controller.yaml",
    "kubernetes/flux-system/controllers/patches/helm-controller.yaml",
)

CONTROLLER_EXPORT = "kubernetes/flux-system/controllers/gotk-components.yaml"


def controller_arguments(root=REPO_ROOT):
    """``{(namespace, name): [argument, …]}`` for every pinned controller.

    Read from the generated export rather than declared, so the requirements
    that depend on a flag track the install: the day a controller stops leader-
    electing, its Lease grant stops being required here too.
    """

    root = Path(root)
    for relative in CONTROLLER_DEPLOYMENT_PATCH_FILES:
        text = (root / relative).read_text(encoding="utf-8")
        for operation, target in re.findall(
            r"(?m)^-\s*op:\s*(\S+)\s*$\n^\s*path:\s*(\S+)\s*$", text
        ):
            if "/args" not in target:
                continue
            if operation != "add" or not target.endswith("/args/-"):
                raise AssertionError(
                    "{} patches the controller argument list with `{} {}`. This "
                    "enumeration reads --enable-leader-election out of the "
                    "generated export, which is only sound while patches can add "
                    "arguments and never remove or replace them.".format(
                        relative, operation, target
                    )
                )
    text = (root / CONTROLLER_EXPORT).read_text(encoding="utf-8")
    arguments = {}
    for chunk in re.split(r"(?m)^---\s*$", text):
        if not re.search(r"(?m)^kind:\s*Deployment\s*$", chunk):
            continue
        name = re.search(r"(?m)^  name:\s*(\S+)\s*$", chunk)
        namespace = re.search(r"(?m)^  namespace:\s*(\S+)\s*$", chunk)
        if name is None or namespace is None:
            raise AssertionError(
                "a Deployment in " + CONTROLLER_EXPORT + " has no readable identity"
            )
        arguments[(namespace.group(1), name.group(1))] = re.findall(
            r"(?m)^\s*-\s*(--\S+)\s*$", chunk
        )
    if not arguments:
        raise AssertionError(
            "no controller Deployment found in " + CONTROLLER_EXPORT
        )
    return arguments


def leader_election_controllers(root=REPO_ROOT):
    """``(namespace, name)`` for every pinned Deployment that leader-elects."""

    electing = sorted(
        key
        for key, arguments in controller_arguments(root).items()
        if LEADER_ELECTION_FLAG in arguments
    )
    if not electing:
        # Every reviewed controller leader-elects today. Zero would silently
        # delete a whole class of requirement, so it is refused rather than
        # reported as "nothing needed".
        raise AssertionError(
            "no controller Deployment in {} carries {}: the leader-election "
            "requirement cannot vanish silently".format(
                CONTROLLER_EXPORT, LEADER_ELECTION_FLAG
            )
        )
    return electing


def cluster_watching_controllers(root=REPO_ROOT):
    """``(namespace, name)`` for every controller whose informers are cluster-wide.

    This is what makes a CLUSTER-scoped grant on a controller's own custom
    resources derived rather than assumed: with ``--watch-all-namespaces=true``
    the controller opens one cluster-wide list/watch per registered kind, which
    a namespaced Role cannot satisfy at all. Drop the flag and the cluster-scoped
    requirement disappears with it.
    """

    watching = sorted(
        key
        for key, arguments in controller_arguments(root).items()
        if WATCH_ALL_NAMESPACES_FLAG in arguments
    )
    if not watching:
        raise AssertionError(
            "no controller Deployment in {} carries {}: the cluster-scoped "
            "informer requirement cannot vanish silently".format(
                CONTROLLER_EXPORT, WATCH_ALL_NAMESPACES_FLAG
            )
        )
    return watching


# The apiGroups whose objects are Flux's own custom resources. A document in one
# of these groups that this module cannot classify is REFUSED: it is a
# reconciliation input — a source, an execution object, or an identity selector —
# and treating it as an ordinary applied object would leave its controller-side
# authority (impersonation, source resolution, status ownership) underived.
KUSTOMIZE_API_GROUP = "kustomize.toolkit.fluxcd.io"
HELM_API_GROUP = "helm.toolkit.fluxcd.io"
SOURCE_API_GROUP = "source.toolkit.fluxcd.io"

# The Flux API domain as LABELS, not as a string to match against. Every string
# form of a domain check is wrong in some direction — `startswith` admits
# `kustomize.toolkit.fluxcd.io.attacker.example` on a bare prefix, `endswith`
# admits `notkustomize.toolkit.fluxcd.io`, and `in` admits both — so a dotted
# name is compared the way it is structured: label by label. (CodeQL's
# py/incomplete-url-substring-sanitization flagged the prefix tests that used to
# be here, and the security framing is wrong for an apiGroup while the
# underlying complaint is right: this decided identity by string shape.)
FLUX_API_DOMAIN = ("toolkit", "fluxcd", "io")

# The kinds this module classifies, and the ONE apiGroup each of them may carry.
# A classified kind in any other group is refused rather than passed through:
# KIND_RESOURCES maps a kind to its group, so a pass-through would derive
# authority against a group the object is not in.
CLASSIFIED_KIND_GROUPS = dict(
    [("Kustomization", KUSTOMIZE_API_GROUP), ("HelmRelease", HELM_API_GROUP)]
    + [(kind, SOURCE_API_GROUP) for kind in SOURCE_KINDS]
)


def _api_group(api_version):
    """The apiGroup of a `group/version` string, exactly.

    Returns ``""`` for the core group (a bare ``v1``) and ``None`` for anything
    that is not exactly one group and one version — an apiVersion with no
    version, with an empty half, or with extra path segments is not a shape this
    enumeration will guess at.
    """

    parts = api_version.split("/")
    if len(parts) == 1:
        return ""
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return parts[0]


def _is_flux_group(group):
    """Whether ``group`` is the Flux API domain or a subdomain of it."""

    labels = tuple(group.split("."))
    return len(labels) >= len(FLUX_API_DOMAIN) and labels[-len(FLUX_API_DOMAIN):] == FLUX_API_DOMAIN


def _mentions_flux_domain(api_version):
    """Whether the Flux domain appears anywhere in ``api_version`` as labels.

    Deliberately broader than :func:`_is_flux_group`, and used only on the
    REFUSAL path: a malformed apiVersion that names the Flux domain somewhere —
    `kustomize.toolkit.fluxcd.io` with no version, or
    `kustomize.toolkit.fluxcd.io.attacker.example/v1` — is a reconciliation
    input this module could not classify, and refusing it is the fail-closed
    direction. Compared as labels for the same reason as above.
    """

    labels = tuple(part for part in re.split(r"[./]", api_version) if part)
    span = len(FLUX_API_DOMAIN)
    return any(
        labels[index:index + span] == FLUX_API_DOMAIN
        for index in range(max(len(labels) - span + 1, 0))
    )


def _classify_flux_document(document, origin, kustomizations, helm_releases, sources):
    kind = document.get("kind")
    api_version = document.get("apiVersion") or ""
    group = _api_group(api_version)
    if kind == "Kustomization" and group == KUSTOMIZE_API_GROUP:
        kustomizations.append(document)
        return True
    if kind == "HelmRelease" and group == HELM_API_GROUP:
        helm_releases.append(document)
        return True
    if kind in SOURCE_KINDS and group == SOURCE_API_GROUP:
        sources.append(document)
        return True
    # Every refusal below is the fail-closed direction: a near-miss stops the
    # derivation with a named error instead of being read as an ordinary applied
    # object whose controller-side authority nobody derived.
    #
    # Order matters: the shape first, then the identity, then the domain. Each
    # message names the most specific thing that is wrong.
    if group is None:
        raise AssertionError(
            "{} declares apiVersion {!r} for {}, which is not exactly one "
            "apiGroup and one version. This enumeration decides authority from "
            "the group, so it refuses a shape it would have to guess at.".format(
                origin, api_version, kind
            )
        )
    # A KIND this module classifies, carried in a group it does not know, is the
    # mis-attribution case: `KIND_RESOURCES` maps a kind to its apiGroup, so
    # letting a `Kustomization` in some other group fall through would derive
    # applied-object authority against `kustomize.toolkit.fluxcd.io` for an
    # object that is not in it — a group it is not in, which is exactly what the
    # extra-path-segment row used to do.
    expected_group = CLASSIFIED_KIND_GROUPS.get(kind)
    if expected_group is not None:
        raise AssertionError(
            "{} declares {} in apiGroup {!r}, but this enumeration knows {} only "
            "in {!r}. Deriving authority for it would attribute the object to a "
            "group it is not in.".format(
                origin, kind, group, kind, expected_group
            )
        )
    if (group and _is_flux_group(group)) or _mentions_flux_domain(api_version):
        raise AssertionError(
            "{} declares {} {}, a Flux custom resource this enumeration cannot "
            "classify. Teach flux_custom_resources about it — an unclassified "
            "reconciliation input reaches the cluster with no controller-side "
            "authority derived for it at all.".format(
                origin, api_version, kind
            )
        )
    return False


def flux_custom_resources(root=REPO_ROOT):
    """Every Flux custom resource in the reviewed desired state.

    Discovered by FOLLOWING the reconciliation graph — the bootstrap-applied
    root, then each Kustomization's ``spec.path`` through its Kustomize roots —
    rather than by globbing known directories. A glob only finds custom
    resources where someone remembered to look: a HelmRelease added under a
    reconciled path that no glob covers reconciles for real, names a
    ServiceAccount helm-controller may not impersonate, and leaves this proof
    green. The walk reaches whatever the reconciliation reaches, and refuses
    what it cannot classify.

    The sources matter on their own account: source-controller reconciles them
    under its own identity, and the other two controllers read them to resolve
    an artifact. An enumeration that stopped at Kustomizations and HelmReleases
    would leave underived the authority every reconciliation starts with.
    """

    root = Path(root)
    kustomizations = []
    helm_releases = []
    sources = []
    # The root Kustomization and its GitRepository are applied by bootstrap, not
    # by a reconciliation, so they are the one hard-coded entry point.
    entry = root / "kubernetes/flux-system/gotk-sync.yaml"
    pending = []
    for document in load_documents(entry):
        if _classify_flux_document(document, entry, kustomizations, helm_releases, sources):
            if document.get("kind") == "Kustomization":
                pending.append(document)
    if not pending:
        raise AssertionError(
            "no root Kustomization found in " + str(entry) + ": the reconciliation "
            "graph has no entry point and every requirement below it would vanish"
        )
    seen_paths = set()
    while pending:
        kustomization = pending.pop()
        relative = kustomization["spec"]["path"].lstrip("./")
        if relative in seen_paths:
            continue
        seen_paths.add(relative)
        for path in _kustomization_paths(root, relative):
            for document in load_documents(path):
                if _classify_flux_document(
                    document, path, kustomizations, helm_releases, sources
                ) and document.get("kind") == "Kustomization":
                    pending.append(document)
    return FluxResources(kustomizations, helm_releases, sources)


def derive_requirements(root=REPO_ROOT):
    """Enumerate every authorization the reviewed desired state depends on.

    Returns ``(requirements, controller_requirements)``: what each impersonated
    reconciler account needs to apply its objects, and what the controllers need
    under their own identity to run the reconciliation at all.
    """

    root = Path(root)
    resources = flux_custom_resources(root)
    requirements = []
    controller = []
    kustomize_controller = Subject(FLUX_SYSTEM, "kustomize-controller")
    helm_controller = Subject(FLUX_SYSTEM, "helm-controller")
    source_controller = Subject(FLUX_SYSTEM, "source-controller")
    controllers = (source_controller, kustomize_controller, helm_controller)
    reconciled_namespaces = set()

    def source_reads(subject, ref, default_namespace, owner, reason):
        """Requirements for resolving one ``sourceRef``/``chartRef``.

        Read under the controller's own identity, before impersonation is
        configured — see SOURCE_READ_VERBS.
        """

        kind = ref["kind"]
        group, resource, _ = _kind_tuple(kind)
        namespace = ref.get("namespace", default_namespace)
        return [
            Requirement(
                subject, verb, group, resource, namespace, None, owner,
                "{} resolves its {} source".format(reason, kind),
            )
            for verb in SOURCE_READ_VERBS
        ]

    for kustomization in resources.kustomizations:
        metadata = kustomization["metadata"]
        spec = kustomization["spec"]
        name = metadata["name"]
        namespace = metadata.get("namespace", FLUX_SYSTEM)
        account = spec["serviceAccountName"]
        subject = Subject(namespace, account)
        owner = ("Kustomization", name)
        reason = "Kustomization " + name

        controller.append(
            Requirement(
                kustomize_controller, "impersonate", "", "serviceaccounts",
                namespace, account, owner, reason,
            )
        )
        # `watch` belongs here even though APPLY_VERBS omits it for applied
        # objects: a controller's informer cache over its OWN custom resource is
        # a list+watch, and a controller that cannot watch its CRs does not poll
        # them, it exits.
        for verb in ("get", "list", "watch", "update", "patch"):
            controller.append(
                Requirement(
                    kustomize_controller, verb, "kustomize.toolkit.fluxcd.io",
                    "kustomizations", namespace, None, owner, reason,
                )
            )
        controller.append(
            Requirement(
                kustomize_controller, "patch", "kustomize.toolkit.fluxcd.io",
                "kustomizations/status", namespace, None, owner, reason,
            )
        )
        decryption = (spec.get("decryption") or {}).get("secretRef") or {}
        if decryption:
            controller.append(
                Requirement(
                    kustomize_controller, "get", "", "secrets", namespace,
                    decryption.get("name"), owner, reason + " SOPS decryption",
                )
            )

        controller.extend(
            source_reads(
                kustomize_controller, spec["sourceRef"], namespace, owner, reason
            )
        )

        relative = spec["path"].lstrip("./")
        waits = spec.get("wait") is True
        for kind, object_namespace, object_name in objects_applied_by(root, relative):
            group, resource, namespaced = _kind_tuple(kind)
            target = object_namespace if namespaced else None
            reconciled_namespaces.add(target)
            for verb in APPLY_VERBS:
                requirements.append(
                    Requirement(
                        subject, verb, group, resource, target, None, owner,
                        "{} applies {} {}".format(reason, kind, object_name),
                    )
                )
            if waits and kind in WORKLOAD_KINDS:
                # `wait: true` evaluates readiness by walking the workload down
                # to the Pods it creates, under the impersonated identity.
                for read_group, read_resource in READ_BACK_RESOURCES:
                    for verb in READ_BACK_VERBS:
                        requirements.append(
                            Requirement(
                                subject, verb, read_group, read_resource, target,
                                None, owner,
                                "{} waits on {} {}".format(reason, kind, object_name),
                            )
                        )

    for release in resources.helm_releases:
        metadata = release["metadata"]
        spec = release["spec"]
        name = metadata["name"]
        namespace = metadata["namespace"]
        account = spec["serviceAccountName"]
        subject = Subject(namespace, account)
        owner = ("HelmRelease", name)
        reason = "HelmRelease " + name

        controller.append(
            Requirement(
                helm_controller, "impersonate", "", "serviceaccounts",
                namespace, account, owner, reason,
            )
        )
        for verb in ("get", "list", "watch", "update", "patch"):
            controller.append(
                Requirement(
                    helm_controller, verb, "helm.toolkit.fluxcd.io", "helmreleases",
                    namespace, None, owner, reason,
                )
            )
        controller.append(
            Requirement(
                helm_controller, "patch", "helm.toolkit.fluxcd.io", "helmreleases/status",
                namespace, None, owner, reason,
            )
        )
        chart = spec.get("chart")
        if chart:
            # A chart resolved from a source object makes helm-controller create
            # the intermediate HelmChart under its OWN identity, in the source's
            # namespace, after reading that source under the same identity.
            chart_spec = chart["spec"]
            source = (chart_spec.get("sourceRef") or {}).get("namespace", namespace)
            controller.extend(
                source_reads(
                    helm_controller, chart_spec["sourceRef"], namespace, owner, reason
                )
            )
            for verb in ("get", "list", "create", "update", "patch", "delete"):
                controller.append(
                    Requirement(
                        helm_controller, verb, "source.toolkit.fluxcd.io", "helmcharts",
                        source, None, owner, reason + " chart",
                    )
                )
            kinds = chart_kinds(root, chart_spec["chart"].lstrip("./"))
        else:
            controller.extend(
                source_reads(helm_controller, spec["chartRef"], namespace, owner, reason)
            )
            if owner not in SITE_CHART_KINDS:
                raise AssertionError(
                    "{} {} resolves its chart from outside this repository and has "
                    "no declared template kinds. Add it to SITE_CHART_KINDS — a "
                    "release whose kinds are unknown needs no permission here and "
                    "would satisfy every sufficiency assertion below.".format(*owner)
                )
            kinds = SITE_CHART_KINDS[owner]

        reconciled_namespaces.add(namespace)
        rendered = list(kinds)
        for kind in rendered + [HELM_STORAGE_KIND]:
            group, resource, namespaced = _kind_tuple(kind)
            target = namespace if namespaced else None
            for verb in APPLY_VERBS:
                requirements.append(
                    Requirement(
                        subject, verb, group, resource, target, None, owner,
                        "{} renders {}".format(reason, kind)
                        if kind != HELM_STORAGE_KIND
                        else reason + " stores its release state",
                    )
                )
        # Helm waits for the release unless an action disables it, and neither
        # action disables it here, so readiness is evaluated by reading the
        # workload chain back under the impersonated identity.
        waits = not any(
            (spec.get(action) or {}).get("disableWait") is True
            for action in ("install", "upgrade")
        )
        if waits and any(kind in WORKLOAD_KINDS for kind in rendered):
            for read_group, read_resource in READ_BACK_RESOURCES:
                for verb in READ_BACK_VERBS:
                    requirements.append(
                        Requirement(
                            subject, verb, read_group, read_resource, namespace, None,
                            owner, reason + " waits for its release to become ready",
                        )
                    )

    # Source objects, reconciled by source-controller under its own identity.
    for source_object in resources.sources:
        metadata = source_object["metadata"]
        kind = source_object["kind"]
        group, resource, _ = _kind_tuple(kind)
        source_namespace = metadata.get("namespace", FLUX_SYSTEM)
        source_reason = "{} {}".format(kind, metadata["name"])
        for verb in SOURCE_OWNER_VERBS:
            controller.append(
                Requirement(
                    source_controller, verb, group, resource, source_namespace, None,
                    (kind, metadata["name"]),
                    source_reason + " is reconciled by source-controller",
                )
            )
        controller.append(
            Requirement(
                source_controller, "patch", group, resource + "/status",
                source_namespace, None, (kind, metadata["name"]),
                source_reason + " status is owned by source-controller",
            )
        )

    # helm-controller creates a HelmChart that source-controller must then
    # reconcile. It appears in no manifest, so it is derived from the release
    # whose chart source causes it to exist.
    for release in resources.helm_releases:
        chart = release["spec"].get("chart") or {}
        if not chart:
            continue
        chart_namespace = (chart["spec"].get("sourceRef") or {}).get(
            "namespace", release["metadata"]["namespace"]
        )
        for verb in SOURCE_OWNER_VERBS:
            controller.append(
                Requirement(
                    source_controller, verb, "source.toolkit.fluxcd.io", "helmcharts",
                    chart_namespace, None, ("HelmChart", release["metadata"]["name"]),
                    "the HelmChart helm-controller derives from this release",
                )
            )

    # Cluster metadata and event reporting, required of all three controllers so
    # that deleting any of them from the narrowed ClusterRole fails here rather
    # than being defended only by prose and the bootstrap mirror.
    non_resource = []
    for subject in controllers:
        for group, resource, verbs, why in CONTROLLER_BASELINE_GRANTS:
            for verb in verbs:
                controller.append(
                    Requirement(subject, verb, group, resource, None, None, ("Controller", "baseline"), why)
                )
        # The controller's own runtime authority, inside its own namespace. It
        # comes from what the process does, not from what the desired state
        # applies, so it is declared — and asserted, so a narrowing that drops it
        # fails here instead of on the cluster.
        for group, resource, verbs, why in CONTROLLER_RUNTIME_GRANTS:
            for verb in verbs:
                controller.append(
                    Requirement(
                        subject, verb, group, resource, subject.namespace, None,
                        ("Controller", "runtime"), why,
                    )
                )
        for verb in EVENT_VERBS:
            for target in sorted(
                namespace for namespace in reconciled_namespaces if namespace
            ):
                controller.append(
                    Requirement(
                        subject, verb, "", "events", target, None,
                        ("Controller", "baseline"),
                        "an Event is written in the namespace of the object it describes",
                    )
                )
        non_resource.append(
            NonResourceRequirement(
                subject, "head", LIVENESS_URL,
                "the API-server liveness probe distinguishes an unreachable "
                "control plane from a failing reconciliation",
            )
        )

    # The custom resources each controller reconciles under its own identity,
    # at CLUSTER scope because `--watch-all-namespaces=true` makes every
    # registered informer a cluster-wide list/watch. Derived from the registered
    # kinds rather than from the objects that exist, so a source grant cannot be
    # deleted just because today's desired state happens to contain no object of
    # that kind — the controller would still fail to start.
    watching = set(cluster_watching_controllers(root))
    for namespace, name in sorted(watching):
        subject = Subject(namespace, name)
        for kind in REGISTERED_CONTROLLERS.get(name, ()):
            group, resource, _ = _kind_tuple(kind)
            for verb in OWNED_RESOURCE_VERBS:
                controller.append(
                    Requirement(
                        subject, verb, group, resource, None, None,
                        ("Controller", "registered"),
                        "{} registers a {} reconciler and watches it across all "
                        "namespaces".format(name, kind),
                    )
                )
            for verb in OWNED_STATUS_VERBS:
                controller.append(
                    Requirement(
                        subject, verb, group, resource + "/status", None, None,
                        ("Controller", "registered"),
                        "{} owns the status of every {}".format(name, kind),
                    )
                )
            for verb in OWNED_FINALIZER_VERBS:
                controller.append(
                    Requirement(
                        subject, verb, group, resource + "/finalizers", None, None,
                        ("Controller", "registered"),
                        "{} manages the finalizer of every {}".format(name, kind),
                    )
                )

    # Leader election, derived from the pinned Deployments' own arguments.
    for namespace, name in leader_election_controllers(root):
        subject = Subject(namespace, name)
        for verb in LEADER_ELECTION_VERBS:
            controller.append(
                Requirement(
                    subject, verb, "coordination.k8s.io", "leases", namespace, None,
                    ("Controller", "leader-election"),
                    "{} runs with {} and takes its Lease before it reconciles "
                    "anything".format(name, LEADER_ELECTION_FLAG),
                )
            )

    return DerivedRequirements(requirements, controller, non_resource)


def suspended_owners(root=REPO_ROOT):
    """Every custom resource — Kustomization OR HelmRelease — that is suspended.

    A declared authorization gap is only tolerable while the object that would
    hit it is switched off, and a HelmRelease is switched off by its own
    ``spec.suspend`` independently of the Kustomization that delivers it. Both
    kinds carry gaps here, so both are tracked.
    """

    resources = flux_custom_resources(Path(root))
    return {
        (item["kind"], item["metadata"]["name"])
        for item in list(resources.kustomizations) + list(resources.helm_releases)
        if item["spec"].get("suspend") is True
    }


def unmet(authorizer, requirements):
    """Return the requirements the committed authorization does not permit."""

    return [
        requirement
        for requirement in requirements
        if not authorizer.allows(
            requirement.subject,
            requirement.verb,
            requirement.group,
            requirement.resource,
            requirement.namespace,
            requirement.name,
        )
    ]


# ---------------------------------------------------------------------------
# The other direction: granted ⊆ derived
# ---------------------------------------------------------------------------
#
# Sufficiency alone says nothing about narrowness. A deny-list of forbidden
# requests only refuses what somebody thought to enumerate, so `+delete` on
# kustomizations, a cluster-wide `pods/exec` read, a `batch/jobs` write, or a
# whole new Role granting Deployment writes to a controller all pass every
# deny-list, every structural check, and the bootstrap mirror once the mutation
# is applied to the mirror too. What closes it is the complement: every request
# the committed authorization GRANTS must be one the derivation asks for, or an
# explicitly declared piece of slack with a stated reason.


class GrantedRequest(NamedTuple):
    """One atomic authorization the committed RBAC actually confers."""

    subject: Subject
    #: The namespace a RoleBinding confines this to, or ``None`` for a
    #: ClusterRoleBinding, which confers it in every namespace and at cluster
    #: scope.
    scope: object
    verb: str
    #: ``None`` marks a non-resource URL grant, where ``resource`` is the URL.
    group: object
    resource: str
    name: object

    def describe(self):
        where = "cluster-wide" if self.scope is None else "in " + str(self.scope)
        if self.group is None:
            return "{} may {} the non-resource URL {} {}".format(
                self.subject, self.verb, self.resource, where
            )
        named = "" if self.name is None else " named " + str(self.name)
        return "{} may {} {}/{}{} {}".format(
            self.subject, self.verb, self.group or "core", self.resource, named, where
        )


# Grants whose CLUSTER scope is a property of Kubernetes rather than a choice,
# so a derived requirement in some namespace justifies the cluster-wide grant.
# Everything else must be derived at cluster scope to be granted at cluster
# scope, which is what stops a namespaced need from being satisfied by a
# cluster-wide rule.
#
# The exemption belongs to the CONTROLLERS ALONE, and the subject is checked as
# well as the apiGroup. Its justification is the controllers' cluster-wide
# informer caches — a property of the three controller ServiceAccounts and of no
# other account here. An impersonated reconciler opens no informer: it applies a
# fixed set of objects in one namespace, so a cluster-scoped grant to one is
# never "by design", it is cross-tenant authority. Keyed on the apiGroup alone,
# this exemption let a ClusterRole grant `naranjo-online-reconciler` write
# authority over every OCIRepository and HelmRelease in the cluster — including
# the other site's — with every gate green. That is safety invariant 14's exact
# class, so the predicate takes the subject.
CLUSTER_SCOPED_BY_DESIGN = {
    "source.toolkit.fluxcd.io": "a controller's informer cache over its custom "
    "resources is a cluster-wide list/watch; a namespaced grant cannot satisfy it",
    "kustomize.toolkit.fluxcd.io": "same informer cache",
    "helm.toolkit.fluxcd.io": "same informer cache",
    ("", "events"): "an Event is written in the namespace of the object it "
    "describes, which is every namespace a reconciliation touches",
}


def _cluster_scope_is_by_design(subject, group, resource):
    # The subjects with cluster-wide informers are exactly the controllers that
    # register reconcilers, which is where the justification comes from — so the
    # set is read from REGISTERED_CONTROLLERS rather than listed a second time.
    if subject.namespace != FLUX_SYSTEM or subject.name not in REGISTERED_CONTROLLERS:
        return False
    return group in CLUSTER_SCOPED_BY_DESIGN or (group, resource) in CLUSTER_SCOPED_BY_DESIGN


def _rule_atoms(rule):
    """Expand one RBAC rule into the atomic requests it authorizes.

    A wildcard expands to the literal ``*``, which matches no derived
    requirement — so a wildcard rule reaching a Flux account is reported as
    ungrounded authority rather than quietly covering everything.
    """

    verbs = rule.get("verbs") or []
    if "nonResourceURLs" in rule:
        for verb in verbs:
            for url in rule.get("nonResourceURLs") or []:
                yield (verb, None, url, None)
        return
    for verb in verbs:
        for group in rule.get("apiGroups") or []:
            for resource in rule.get("resources") or []:
                for name in rule.get("resourceNames") or [None]:
                    yield (verb, group, resource, name)


def rbac_subjects_and_namespaces(documents):
    """Every account the reviewed RBAC can reach, and every namespace it binds in.

    Both sets are read from the documents rather than declared, so a Role,
    RoleBinding, or ServiceAccount added anywhere — including a namespace this
    change never mentions — is inside the narrowness proof automatically.
    """

    def account(namespace, name):
        if not isinstance(namespace, str) or not isinstance(name, str):
            raise AssertionError(
                "a ServiceAccount identity in the reviewed RBAC is incomplete: "
                "{!r}/{!r}".format(namespace, name)
            )
        subjects.add(Subject(namespace, name))
        namespaces.add(namespace)

    subjects = set()
    namespaces = set()
    for document in documents:
        kind = document.get("kind")
        metadata = document.get("metadata") or {}
        if kind == "ServiceAccount":
            account(metadata.get("namespace"), metadata.get("name"))
            continue
        if kind not in {"RoleBinding", "ClusterRoleBinding"}:
            continue
        if kind == "RoleBinding":
            namespaces.add(metadata.get("namespace"))
        for entry in document.get("subjects") or []:
            if entry.get("kind") == "ServiceAccount":
                account(entry.get("namespace"), entry.get("name"))
    return subjects, {namespace for namespace in namespaces if namespace}


def granted_requests(authorizer, subjects, namespaces):
    """Every atomic request the committed authorization confers on ``subjects``.

    Cluster-scoped and namespaced grants are separated deliberately: a rule that
    a ClusterRoleBinding confers everywhere is reported once, at cluster scope,
    and only the SURPLUS a RoleBinding adds inside a namespace is reported
    against that namespace. Without the subtraction every cluster-wide grant
    would also be reported as a per-namespace grant and the two could not be
    told apart.
    """

    granted = set()
    for subject in sorted(subjects):
        cluster = {
            atom
            for rule in authorizer.rules_for_subject(subject, None)
            for atom in _rule_atoms(rule)
        }
        for atom in cluster:
            granted.add(GrantedRequest(subject, None, *atom))
        for namespace in sorted(namespaces):
            local = {
                atom
                for rule in authorizer.rules_for_subject(subject, namespace)
                for atom in _rule_atoms(rule)
            } - cluster
            for atom in local:
                granted.add(GrantedRequest(subject, namespace, *atom))
    return granted


def ungrounded_grants(granted, derived):
    """The granted requests no derived requirement asks for.

    ``derived`` is a :class:`DerivedRequirements`. The result is what a
    narrowness assertion must compare against a declared-slack allowlist: with
    an empty allowlist the authorization is exactly the derivation, and every
    row that is not exactly the derivation has to be written down and justified.
    """

    resource_index = set()
    namespaces_by_key = {}
    for requirement in list(derived.applied) + list(derived.controller):
        key = (
            requirement.subject, requirement.verb, requirement.group,
            requirement.resource, requirement.name,
        )
        resource_index.add(key + (requirement.namespace,))
        namespaces_by_key.setdefault(key, set()).add(requirement.namespace)
    non_resource_index = {
        (requirement.subject, requirement.verb, requirement.url)
        for requirement in derived.non_resource
    }

    ungrounded = set()
    for request in granted:
        if request.group is None:
            if (request.subject, request.verb, request.resource) in non_resource_index:
                continue
            ungrounded.add(request)
            continue
        key = (request.subject, request.verb, request.group, request.resource, request.name)
        if key + (request.scope,) in resource_index:
            continue
        if (
            request.scope is None
            and _cluster_scope_is_by_design(request.subject, request.group, request.resource)
            and namespaces_by_key.get(key)
        ):
            continue
        ungrounded.add(request)
    return ungrounded
