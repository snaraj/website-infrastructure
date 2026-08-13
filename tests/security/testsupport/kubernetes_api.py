"""A typed in-memory model of the Kubernetes API objects this flow touches.

Three kinds, no more: ``OCIRepository`` (the chart source), ``HelmRelease``
(the release), and ``Deployment`` (the rollout outcome). The model reproduces
the API behaviors the sync contract actually depends on and nothing else:

* ``metadata.generation`` increments only when ``spec`` changes, which is what
  makes "observed its exact current generation" a meaningful assertion;
* ``status`` is a subresource — writing it never bumps the generation, so a
  controller reporting progress cannot be mistaken for desired-state drift;
* ``metadata.resourceVersion`` advances on every write, so a battery can prove
  a decision left an object genuinely untouched;
* namespaced identity is exact: a cross-namespace read is a miss, not a
  silently widened lookup.

Nothing here talks to a cluster. There is no kubeconfig parameter, no server
address, and no transport: an accidental live call is not merely forbidden, it
is unrepresentable.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace

OCI_REPOSITORY = "OCIRepository"
HELM_RELEASE = "HelmRelease"
DEPLOYMENT = "Deployment"
KNOWN_KINDS = frozenset({OCI_REPOSITORY, HELM_RELEASE, DEPLOYMENT})


class NotFound(KeyError):
    """No object of that kind exists at that exact namespace/name."""


class UnknownKind(KeyError):
    """The model refuses to invent an object kind it does not implement."""


@dataclass(frozen=True)
class ObjectMeta:
    """The metadata fields the sync contract reasons about."""

    name: str
    namespace: str
    generation: int = 1
    resource_version: int = 1

    @property
    def identity(self) -> tuple[str, str]:
        return (self.namespace, self.name)


@dataclass(frozen=True)
class KubernetesObject:
    """One stored object: kind, metadata, desired spec, reported status."""

    kind: str
    api_version: str
    metadata: ObjectMeta
    spec: dict
    status: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def namespace(self) -> str:
        return self.metadata.namespace

    def condition(self, condition_type: str):
        """Return the single condition of a type, or ``None``.

        Deliberately returns ``None`` when a type appears more than once: a
        duplicated ``Ready`` condition is ambiguous evidence, and ambiguous
        evidence is treated as absent.
        """

        matches = [
            item
            for item in self.status.get("conditions", [])
            if isinstance(item, dict) and item.get("type") == condition_type
        ]
        return matches[0] if len(matches) == 1 else None

    def is_ready(self) -> bool:
        condition = self.condition("Ready")
        return bool(condition) and condition.get("status") == "True"


def ready_condition(ready: bool, reason: str, message: str = "") -> dict:
    """Build the one condition shape the model reports."""

    return {
        "type": "Ready",
        "status": "True" if ready else "False",
        "reason": reason,
        "message": message,
    }


class MockKubernetesApi:
    """An apply/patch/get surface over an in-memory object store."""

    def __init__(self) -> None:
        self._objects: dict[tuple[str, str, str], KubernetesObject] = {}
        self._resource_version = 0

    # ------------------------------------------------------------------ reads

    def get(self, kind: str, namespace: str, name: str) -> KubernetesObject:
        if kind not in KNOWN_KINDS:
            raise UnknownKind(kind)
        try:
            return self._objects[(kind, namespace, name)]
        except KeyError:
            raise NotFound("{} {}/{}".format(kind, namespace, name)) from None

    def find(self, kind: str, namespace: str, name: str) -> KubernetesObject | None:
        try:
            return self.get(kind, namespace, name)
        except (NotFound, UnknownKind):
            return None

    def list(self, kind: str) -> list[KubernetesObject]:
        if kind not in KNOWN_KINDS:
            raise UnknownKind(kind)
        return [
            item
            for key, item in sorted(self._objects.items())
            if key[0] == kind
        ]

    # ----------------------------------------------------------------- writes

    def apply(
        self,
        kind: str,
        api_version: str,
        namespace: str,
        name: str,
        spec: dict,
    ) -> KubernetesObject:
        """Create or replace desired state, bumping generation on real change."""

        if kind not in KNOWN_KINDS:
            raise UnknownKind(kind)
        self._resource_version += 1
        key = (kind, namespace, name)
        existing = self._objects.get(key)
        if existing is None:
            stored = KubernetesObject(
                kind=kind,
                api_version=api_version,
                metadata=ObjectMeta(
                    name=name,
                    namespace=namespace,
                    generation=1,
                    resource_version=self._resource_version,
                ),
                spec=copy.deepcopy(spec),
                status={},
            )
        else:
            changed = existing.spec != spec or existing.api_version != api_version
            stored = replace(
                existing,
                api_version=api_version,
                spec=copy.deepcopy(spec),
                metadata=replace(
                    existing.metadata,
                    generation=existing.metadata.generation + (1 if changed else 0),
                    resource_version=self._resource_version,
                ),
            )
        self._objects[key] = stored
        return stored

    def patch_status(
        self, kind: str, namespace: str, name: str, status: dict
    ) -> KubernetesObject:
        """Merge into the status subresource without touching the generation."""

        existing = self.get(kind, namespace, name)
        self._resource_version += 1
        merged = dict(existing.status)
        merged.update(copy.deepcopy(status))
        stored = replace(
            existing,
            status=merged,
            metadata=replace(
                existing.metadata, resource_version=self._resource_version
            ),
        )
        self._objects[(kind, namespace, name)] = stored
        return stored

    def delete(self, kind: str, namespace: str, name: str) -> None:
        self.get(kind, namespace, name)
        self._resource_version += 1
        del self._objects[(kind, namespace, name)]
