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


def effective_flux_rbac(root=REPO_ROOT):
    """The RBAC the cluster would hold: generated export + patches + access.yaml."""

    root = Path(root)
    base = load_rbac_documents(root / "kubernetes/flux-system/controllers/gotk-components.yaml")
    patches = []
    for relative in FLUX_RBAC_PATCH_FILES:
        patches.extend(load_documents(root / relative))
    documents = apply_patches(base, patches)
    documents.extend(load_documents(root / "kubernetes/flux-system/access.yaml"))
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
        return authorizer

    @classmethod
    def from_paths(cls, paths):
        documents = []
        for path in paths:
            documents.extend(load_documents(path))
        return cls.from_documents(documents)

    def _rules_for(self, binding, binding_namespace):
        role_ref = binding.get("roleRef") or {}
        if role_ref.get("kind") == "ClusterRole":
            return self.cluster_roles.get(role_ref.get("name"), [])
        return self.roles.get((binding_namespace, role_ref.get("name")), [])

    def _binds(self, binding, subject):
        for entry in binding.get("subjects") or []:
            if entry.get("kind") != "ServiceAccount":
                continue
            if (entry.get("namespace"), entry.get("name")) == tuple(subject):
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

    def allows(self, subject, verb, group, resource, namespace=None, name=None):
        for rule in self.rules_for_subject(subject, namespace):
            if not _matches(rule.get("verbs") or [], verb):
                continue
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
    "ConfigMap": ("", "configmaps", True),
    "Deployment": ("apps", "deployments", True),
    "GitRepository": ("source.toolkit.fluxcd.io", "gitrepositories", True),
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
SITE_CHART_KINDS = {
    "naranjo-online": ("Deployment", "Service", "ServiceAccount", "NetworkPolicy"),
    "lidersea-com": ("Deployment", "Service", "ServiceAccount", "NetworkPolicy"),
}

# Helm keeps one release-state Secret per revision in the release namespace, so
# every HelmRelease implies Secret authority for the account it runs as.
HELM_STORAGE_KIND = "Secret"

FLUX_SYSTEM = "flux-system"


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
    #: The Flux custom resource whose reconciliation needs this authorization.
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


def _kustomization_paths(root, relative):
    """Every manifest file a Kustomize root pulls in, recursively."""

    base = root / relative
    index = base / "kustomization.yaml"
    documents = load_documents(index)
    if not documents:
        # An empty or unreadable Kustomize root would silently contribute zero
        # objects, which is indistinguishable from "everything is authorized".
        raise AssertionError("no Kustomize root parsed at " + str(index))
    resources = documents[0].get("resources") or []
    files = []
    for entry in resources:
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
    return applied


def chart_kinds(root, relative):
    """Kinds a chart in THIS repository renders.

    Helm templates are not YAML until Helm has run, so the kinds are read the
    way the repository's other gates read them: the ``kind:`` field of each
    template document.
    """

    kinds = []
    for path in sorted((root / relative / "templates").glob("*.yaml")):
        kinds.extend(re.findall(r"(?m)^kind:\s*(\S+)\s*$", path.read_text(encoding="utf-8")))
    return kinds


def flux_custom_resources(root):
    """Every Flux Kustomization and HelmRelease in the reviewed desired state."""

    kustomizations = []
    helm_releases = []
    paths = [root / "kubernetes/flux-system/gotk-sync.yaml"]
    paths.extend(sorted((root / "kubernetes/reconciliation").glob("*.yaml")))
    paths.extend(sorted((root / "kubernetes/websites").glob("*/release.yaml")))
    paths.append(root / "kubernetes/platform/cloudflare-public/release/release.yaml")
    for path in paths:
        for document in load_documents(path):
            if document.get("kind") == "Kustomization" and document.get(
                "apiVersion", ""
            ).startswith("kustomize.toolkit.fluxcd.io/"):
                kustomizations.append(document)
            elif document.get("kind") == "HelmRelease":
                helm_releases.append(document)
    return kustomizations, helm_releases


def derive_requirements(root=REPO_ROOT):
    """Enumerate every authorization the reviewed desired state depends on.

    Returns ``(requirements, controller_requirements)``: what each impersonated
    reconciler account needs to apply its objects, and what the controllers need
    under their own identity to run the reconciliation at all.
    """

    root = Path(root)
    kustomizations, helm_releases = flux_custom_resources(root)
    requirements = []
    controller = []
    kustomize_controller = Subject(FLUX_SYSTEM, "kustomize-controller")
    helm_controller = Subject(FLUX_SYSTEM, "helm-controller")

    for kustomization in kustomizations:
        metadata = kustomization["metadata"]
        spec = kustomization["spec"]
        name = metadata["name"]
        namespace = metadata.get("namespace", FLUX_SYSTEM)
        account = spec["serviceAccountName"]
        subject = Subject(namespace, account)
        reason = "Kustomization " + name

        controller.append(
            Requirement(
                kustomize_controller, "impersonate", "", "serviceaccounts",
                namespace, account, name, reason,
            )
        )
        for verb in ("get", "list", "update", "patch"):
            controller.append(
                Requirement(
                    kustomize_controller, verb, "kustomize.toolkit.fluxcd.io",
                    "kustomizations", namespace, None, name, reason,
                )
            )
        controller.append(
            Requirement(
                kustomize_controller, "patch", "kustomize.toolkit.fluxcd.io",
                "kustomizations/status", namespace, None, name, reason,
            )
        )
        decryption = (spec.get("decryption") or {}).get("secretRef") or {}
        if decryption:
            controller.append(
                Requirement(
                    kustomize_controller, "get", "", "secrets", namespace,
                    decryption.get("name"), name, reason + " SOPS decryption",
                )
            )

        relative = spec["path"].lstrip("./")
        for kind, object_namespace, object_name in objects_applied_by(root, relative):
            group, resource, namespaced = _kind_tuple(kind)
            target = object_namespace if namespaced else None
            for verb in APPLY_VERBS:
                requirements.append(
                    Requirement(
                        subject, verb, group, resource, target, None, name,
                        "{} applies {} {}".format(reason, kind, object_name),
                    )
                )

    for release in helm_releases:
        metadata = release["metadata"]
        spec = release["spec"]
        name = metadata["name"]
        namespace = metadata["namespace"]
        account = spec["serviceAccountName"]
        subject = Subject(namespace, account)
        reason = "HelmRelease " + name

        controller.append(
            Requirement(
                helm_controller, "impersonate", "", "serviceaccounts",
                namespace, account, name, reason,
            )
        )
        for verb in ("get", "list", "update", "patch"):
            controller.append(
                Requirement(
                    helm_controller, verb, "helm.toolkit.fluxcd.io", "helmreleases",
                    namespace, None, name, reason,
                )
            )
        controller.append(
            Requirement(
                helm_controller, "patch", "helm.toolkit.fluxcd.io", "helmreleases/status",
                namespace, None, name, reason,
            )
        )
        chart = spec.get("chart")
        if chart:
            # A chart resolved from a source object makes helm-controller create
            # the intermediate HelmChart under its OWN identity, in the source's
            # namespace.
            source = (chart["spec"].get("sourceRef") or {}).get("namespace", namespace)
            for verb in ("get", "list", "create", "update", "patch", "delete"):
                controller.append(
                    Requirement(
                        helm_controller, verb, "source.toolkit.fluxcd.io", "helmcharts",
                        source, None, name, reason + " chart",
                    )
                )
            kinds = chart_kinds(root, chart["spec"]["chart"].lstrip("./"))
        else:
            kinds = SITE_CHART_KINDS[name]

        for kind in list(kinds) + [HELM_STORAGE_KIND]:
            group, resource, namespaced = _kind_tuple(kind)
            target = namespace if namespaced else None
            for verb in APPLY_VERBS:
                requirements.append(
                    Requirement(
                        subject, verb, group, resource, target, None, name,
                        "{} renders {}".format(reason, kind)
                        if kind != HELM_STORAGE_KIND
                        else reason + " stores its release state",
                    )
                )

    return requirements, controller


def suspended_kustomizations(root=REPO_ROOT):
    """Names of the Kustomizations whose reconciliation is switched off."""

    kustomizations, _ = flux_custom_resources(Path(root))
    return {
        item["metadata"]["name"]
        for item in kustomizations
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
