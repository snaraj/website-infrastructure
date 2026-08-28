"""A loopback mock of the OCI registry surface this platform reads.

The platform never pushes or lists tags: it fetches one exact chart manifest
digest and asks whether that digest carries a cosign signature made by an
exact keyless identity. The tag-list route exists only so hostile tests can
prove it was never used. These operations are served over a real loopback
HTTP server, and they
are served over a real ``http.server`` on ``127.0.0.1`` so the client under
test performs genuine HTTP — status codes, headers, JSON bodies, 404s — rather
than calling into a stub that can only say yes.

Signature discovery follows cosign's tag convention: a signature for
``sha256:<hex>`` lives at the tag ``sha256-<hex>.sig`` in the same repository.
The certificate identity is modelled as manifest annotations rather than a real
Fulcio certificate; nothing here verifies a signature cryptographically, and no
battery built on it may claim otherwise (see :mod:`tests.security.testsupport`).
"""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# cosign records the signing certificate's OIDC issuer and identity subject as
# annotations on the signature layer. The model uses the same keys so a reader
# comparing this against a real registry sees the same names.
COSIGN_ISSUER_ANNOTATION = "dev.sigstore.cosign/issuer"
COSIGN_SUBJECT_ANNOTATION = "dev.sigstore.cosign/subject"
HELM_CHART_MEDIA_TYPE = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
ZERO_DIGEST = "sha256:" + ("0" * 64)


def synthetic_digest(seed: str) -> str:
    """Return a deterministic, obviously-synthetic content address."""

    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SigningIdentity:
    """One keyless certificate identity: who signed, and under which issuer."""

    issuer: str
    subject: str


@dataclass
class PublishedChart:
    """One published chart release as a registry would hold it.

    ``image_repository`` and ``image_digest`` are the exact workload identity
    carried by the chart. ``None`` models a missing publish-time binding.
    """

    version: str
    digest: str
    image_repository: str | None = None
    image_digest: str | None = None
    signature: SigningIdentity | None = None
    media_type: str = HELM_CHART_MEDIA_TYPE


class MockRegistryError(RuntimeError):
    """The mock registry was asked for something it does not model."""


class MockOciRegistry:
    """An in-process registry holding published charts for one or more paths.

    Repository paths are the full path after ``/v2/`` — for example
    ``snaraj/charts/naranjo-online`` — so a battery can hold both sites at once
    and prove that one site's client cannot reach the other's artifacts.
    """

    def __init__(self) -> None:
        self._charts: dict[str, dict[str, PublishedChart]] = {}
        self._manifests: dict[str, dict[str, PublishedChart]] = {}
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ---------------------------------------------------------------- content

    def publish(self, repository: str, chart: PublishedChart) -> PublishedChart:
        """Add or replace one version in one repository path.

        Tags may be replaced, while content remains addressable by immutable
        digest. Reusing one digest for different bytes is rejected by the mock
        just as a content-addressed registry must reject it.
        """

        manifests = self._manifests.setdefault(repository, {})
        existing = manifests.get(chart.digest)
        if existing is not None and existing != chart:
            raise MockRegistryError(
                "one content digest cannot identify two different chart manifests"
            )
        manifests[chart.digest] = chart
        self._charts.setdefault(repository, {})[chart.version] = chart
        return chart

    def remove(self, repository: str, version: str) -> None:
        self._charts.get(repository, {}).pop(version, None)

    def chart(self, repository: str, version: str) -> PublishedChart | None:
        return self._charts.get(repository, {}).get(version)

    def tags(self, repository: str) -> list[str]:
        return sorted(self._charts.get(repository, {}))

    # ----------------------------------------------------------------- server

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise MockRegistryError("registry is not serving")
        host, port = self._server.server_address[0], self._server.server_address[1]
        return "http://{}:{}".format(host, port)

    def start(self) -> "MockOciRegistry":
        if self._server is not None:
            raise MockRegistryError("registry is already serving")
        registry = self

        class Handler(BaseHTTPRequestHandler):
            # HTTP/1.0 closes each connection, which keeps the battery fast and
            # deterministic: no keep-alive timeout can stall a client that made
            # exactly one request and expects an immediate answer.
            protocol_version = "HTTP/1.0"

            def log_message(self, *_args):  # noqa: D401 - silence test output
                """Keep the battery's output free of per-request noise."""

            def _respond(self, code, payload=None, headers=None):
                body = b"" if payload is None else json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _route(self):
                path = self.path.split("?", 1)[0]
                if path in {"/v2", "/v2/"}:
                    self._respond(200, {})
                    return
                if not path.startswith("/v2/"):
                    self._respond(404, {"errors": ["unsupported route"]})
                    return
                remainder = path[len("/v2/"):]
                for separator, handler in (
                    ("/tags/list", registry._handle_tags),
                    ("/manifests/", registry._handle_manifest),
                ):
                    if separator == "/tags/list":
                        if remainder.endswith(separator):
                            handler(self, remainder[: -len(separator)])
                            return
                    elif separator in remainder:
                        repository, reference = remainder.split(separator, 1)
                        handler(self, repository, reference)
                        return
                self._respond(404, {"errors": ["unsupported route"]})

            def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler contract
                self._route()

            def do_HEAD(self):  # noqa: N802 - BaseHTTPRequestHandler contract
                self._route()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        # A short poll interval keeps ``stop`` prompt: ``shutdown`` blocks for
        # up to one interval, and a battery that starts a fresh registry per
        # test would otherwise pay the default half-second every time.
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "MockOciRegistry":
        return self.start()

    def __exit__(self, *_exception) -> None:
        self.stop()

    # ---------------------------------------------------------------- routing

    def _handle_tags(self, handler, repository):
        if repository not in self._charts:
            handler._respond(404, {"errors": ["NAME_UNKNOWN"]})
            return
        handler._respond(200, {"name": repository, "tags": self.tags(repository)})

    def _handle_manifest(self, handler, repository, reference):
        versions = self._charts.get(repository)
        if versions is None:
            handler._respond(404, {"errors": ["NAME_UNKNOWN"]})
            return
        if reference.endswith(".sig"):
            self._handle_signature(handler, repository, reference)
            return
        chart = versions.get(reference)
        if chart is None:
            chart = self._manifests.get(repository, {}).get(reference)
        if chart is None:
            handler._respond(404, {"errors": ["MANIFEST_UNKNOWN"]})
            return
        handler._respond(
            200,
            {
                "schemaVersion": 2,
                "config": {"mediaType": "application/vnd.cncf.helm.config.v1+json"},
                "layers": [{"mediaType": chart.media_type, "digest": chart.digest}],
                "annotations": {"org.opencontainers.image.version": chart.version},
                "imageRepository": chart.image_repository,
                "imageDigest": chart.image_digest,
            },
            {"Docker-Content-Digest": chart.digest},
        )

    def _handle_signature(self, handler, repository, reference):
        target = "sha256:" + reference[len("sha256-"):-len(".sig")]
        chart = self._manifests.get(repository, {}).get(target)
        if chart is None or chart.signature is None:
            # An unsigned artifact is indistinguishable from a missing one at
            # this layer, and both must fail closed downstream.
            handler._respond(404, {"errors": ["MANIFEST_UNKNOWN"]})
            return
        handler._respond(
            200,
            {
                "schemaVersion": 2,
                "layers": [
                    {
                        "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                        "annotations": {
                            COSIGN_ISSUER_ANNOTATION: chart.signature.issuer,
                            COSIGN_SUBJECT_ANNOTATION: chart.signature.subject,
                        },
                    }
                ],
            },
        )


@dataclass
class RegistryClient:
    """A ``urllib`` client for exactly the reads the platform performs.

    It is deliberately anonymous: there is no credential parameter, no proxy
    parameter, and no way to supply one, mirroring the desired state's refusal
    of ``secretRef``/``serviceAccountName``/``proxySecretRef`` on chart sources.
    """

    base_url: str
    timeout: float = 5.0
    requests: list[str] = field(default_factory=list)

    def _opener(self):
        """Build an opener that cannot be redirected by ambient proxy settings.

        An exported ``HTTP_PROXY`` (or a macOS system proxy) would otherwise
        send these requests somewhere other than the loopback mock, which would
        make the battery neither hermetic nor honest. The empty ProxyHandler
        also removes the per-call system-configuration lookup that the default
        opener performs.
        """

        return urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _get(self, path):
        url = "{}/v2/{}".format(self.base_url.rstrip("/"), path)
        self.requests.append(path)
        request = urllib.request.Request(url, method="GET")
        try:
            with self._opener().open(request, timeout=self.timeout) as response:
                return response.status, json.loads(response.read().decode("utf-8")), dict(
                    response.headers
                )
        except urllib.error.HTTPError as error:
            # HTTPError is itself a response object; closing it keeps the
            # battery free of ResourceWarning noise that would mask a real one.
            code = error.code
            error.close()
            return code, None, {}

    def list_tags(self, repository):
        """Return published tags, or ``None`` when the path does not exist."""

        status, payload, _ = self._get("{}/tags/list".format(repository))
        if status != 200 or not isinstance(payload, dict):
            return None
        tags = payload.get("tags")
        return list(tags) if isinstance(tags, list) else None

    def manifest(self, repository, reference):
        """Return ``(digest, manifest)`` for a tag or digest, or ``(None, None)``."""

        status, payload, headers = self._get(
            "{}/manifests/{}".format(repository, reference)
        )
        if status != 200 or not isinstance(payload, dict):
            return None, None
        return headers.get("Docker-Content-Digest"), payload

    def signature_identity(self, repository, digest):
        """Return the signing identity for a digest, or ``None`` when unsigned.

        ``None`` covers both "no signature exists" and "the registry refused to
        serve one": the caller must treat them identically and fail closed.
        """

        if not digest or not digest.startswith("sha256:"):
            return None
        tag = "sha256-{}.sig".format(digest[len("sha256:"):])
        status, payload, _ = self._get("{}/manifests/{}".format(repository, tag))
        if status != 200 or not isinstance(payload, dict):
            return None
        layers = payload.get("layers")
        if not isinstance(layers, list) or len(layers) != 1:
            return None
        annotations = layers[0].get("annotations")
        if not isinstance(annotations, dict):
            return None
        issuer = annotations.get(COSIGN_ISSUER_ANNOTATION)
        subject = annotations.get(COSIGN_SUBJECT_ANNOTATION)
        if not isinstance(issuer, str) or not isinstance(subject, str):
            return None
        return SigningIdentity(issuer=issuer, subject=subject)
