# Private obsync TLS boundary

This is a proposed operator-owned transport, not an activation receipt. The
application remains provider-neutral and personal; no public DNS name, public
Tunnel hostname, website route, Access application or paid domain is required.
The private connector's existing namespace name does not make this service
public. Do not create a public endpoint as a prerequisite for private sync.

## Boundary and remaining trust

The intended path is a privately admitted device, the dedicated private-network
connector, `obsync-tls-proxy` ClusterIP TCP 443 / container TCP 8443, then
`obsync` TCP 8080 within `obsidian`. The connector policy selects the proxy,
never the backend; the backend policy selects only the proxy. Kubernetes
NetworkPolicies are additive: verify the effective live union, not just one
object. Conftest rejects additional obsidian policies in reviewed source but is
not a runtime admission controller and cannot stop a privileged operator.

The device validates TLS to the in-cluster proxy using its locally configured
trust and the owner's chosen private hostname. This design requires no Gateway
TLS decryption on this flow; private routing alone does not guarantee that.
Verify the effective inspection settings or a narrowly scoped `Do Not Inspect`
rule and confirm that each device sees the actual origin leaf, not an
inspection certificate. Cloudflare explicitly supports
[TLS inspection of private applications](https://developers.cloudflare.com/learning-paths/replace-vpn/configure-device-agent/enable-tls-decryption/).
Do not enable inspection, install an inspection CA, weaken certificate checks
or switch to a public HTTP Tunnel to make the connection work. A provider
policy change still requires its own scoped authorization.

Only with that verified non-inspecting path does Cloudflare avoid terminating
the inner application TLS session. It remains
trusted for private-network/device admission, routing availability and traffic
metadata, and its installed client is part of the endpoint's trusted software.
This is not the trust model of a public HTTP Tunnel or an Access login. Do not
substitute one silently or add Access credentials to the app.

The proxy terminates TLS and therefore sees application credentials, pairing
traffic and encrypted content envelopes. Proxy-to-app traffic is HTTP inside
the reviewed cluster network. Node administrators, the proxy and the application
process remain trusted for authentication material, including the current
pairing hop. They must not receive the owner's content-decryption keys; encrypted
vault content is a separate application property, not something TLS proves.
This design does not claim protection from a compromised node or TLS terminator.

NGINX passes application authentication headers, cookies and the request target
through unchanged. It strips the specific forwarding/Cloudflare attribution
headers listed in `nginx.conf`; this is not a wildcard promise for every `CF-*`
header. Keep app `edge.mode: none` and the trusted-proxy CIDR list empty. Access
or proxy headers never replace the app's own authentication.

## Artifact and configuration

`kubernetes/platform/obsync-tls-proxy/` renders exactly five objects: Deployment,
ClusterIP Service, tokenless ServiceAccount, immutable hash-named ConfigMap and
NetworkPolicy. There is no Secret, Ingress, LoadBalancer, NodePort, CA service,
certificate controller or public route in that root. It is not included in a
broad Flux reconciliation root by this change.

The upstream unprivileged NGINX image is pinned in `versions.env` and repeated
in the manifest and closed policy. The image runs as UID/GID 101 with all
capabilities dropped, no privilege escalation, a read-only root and a bounded
memory-backed `/tmp`. It starts NGINX directly, without image entrypoint scripts.
Digest and upstream source annotations establish the selected bytes and stated
origin; they are not a cryptographic publisher-signature claim. CI scans the
exact selected proxy image for high/critical known vulnerabilities, without
ignoring unfixed findings.

There is one TLS listener (TLS 1.2/1.3), no cleartext HTTP service or admin API,
no certificate issuance and no request/response cache. Request and response
buffering are disabled; upload size is governed by the app rather than a second
proxy size ceiling. The 300-second upstream read timeout is an inactivity limit;
long-lived streams must emit more frequently. App limits, resource limits and
the bounded worker connections remain relevant under sustained load.

Access and error logs are disabled, including startup error output, to avoid
credential/request capture. This intentionally loses request-level diagnostics:
use local config validation and probe/exit status, not a temporary verbose log
switch on personal traffic. Startup/liveness are TCP checks; readiness proxies
the app's `/readyz` and cannot become healthy merely because NGINX is listening.

## Certificate custody and renewal

The operator supplies only a leaf chain and its matching key in the existing
namespace as `obsync-tls-leaf`, keys `tls.crt` and `tls.key`. The Pod projects
only those two entries, read-only, with group-readable 0440 mode. A CA private
key, DNS API token, application server key and device secret are forbidden in
this Secret or any proxy mount. Keep the issuing CA private key off-cluster.
Do not commit a certificate, key, chosen private hostname or local inventory.

Before activation, verify the selected hostname's SAN, validity period,
server-auth usage, chain, public-key match and device trust without printing key
values. An unknown/expired/wrong-name certificate must fail on each real client;
no `insecureSkipVerify`, local permanent trust bypass or fallback to HTTP.

Renew before expiry through the same operator-controlled custody path. Record
only certificate metadata privately; retain the previous valid leaf/key pair
in its existing authorized recovery custody, not a new repository or service.
Update only the named Secret after confirming its identity, then restart only
this proxy Deployment. NGINX loads certificates on startup; mounted Secret
updates alone do not reload it. `Recreate` incurs a brief interruption, and the
app must reconnect safely. Verify the new served certificate and real client
sync. If renewal fails, restore the previous still-valid pair and restart the
proxy; otherwise leave the private path unavailable. Never fall back to an
unverified leaf, and never delete claims or data as recovery.

## Activation order and acceptance

Owner merge, an explicit operator window and the prerequisites in
[application sync](obsync-application-sync.md) and
[storage admission](storage-admission.md) come first. The exact PVC mount
exception authorizes no disk preparation, StorageClass/PV creation, volume
rebinding or substitute OS-filesystem storage. Missing storage evidence is a
stop, not permission to pick a convenient directory.

Follow this order; a TCP startup check is not backend-dependent readiness:

1. Keep the private path disabled.
   Use the approved composition lane for the app; do not add a competing
   reconciler or apply the broad Flux root.
2. Bind the reviewed application peer.
   Through the reviewed composition, replace its fail-closed pending peer with
   the exact proxy selector and backend port. Verify the effective policy union
   admits only the proxy to the app. This binding must precede proxy readiness:
   the proxy's `/readyz` request must reach the app to succeed.
3. Install and start the reviewed proxy.
   Once the app's Service exists and certificate custody is established, review
   the five-object render from the merged proxy root, check live target
   identities and effective policies, and apply only that reviewed artifact in
   the separately authorized window. Missing evidence or a conflicting existing
   object stops the apply; source publication never permits blind replacement.
4. Require backend-dependent readiness.
   Verify the proxy's HTTPS `/readyz` reaches the ready app, along with the
   intended certificate and policy checks. Config validation and TCP startup
   or liveness alone cannot clear this gate. Keep the private path disabled on
   any failure; never bypass readiness or widen backend access to proceed.
5. Enable the separately approved private path.
   Only after the preceding gates pass, enable the intended device path under
   its own authorization and complete the real-client acceptance below. The
   [isolated connector procedure](obsync-private-connector.md) prepares only
   that connector's policy and Deployment; it leaves shared resources and the
   shared release untouched and requires its own prerequisite/owner checkpoints.

NGINX resolves the backend Service at startup: create that Service first.
Replacing its ClusterIP requires a proxy restart; ordinary app Pod replacement
behind the stable Service does not.
No provider resource is created or exposed by these manifests.

`make check-obsync-proxy` exercises this exact image and config with disposable
leaf credentials and synthetic bytes inside an internal Docker network, with
no published ports or mounted Docker credentials. It checks TLS 1.2/1.3,
untrusted-leaf refusal, header/target/upload preservation, attribution stripping,
incremental responses and absence of the synthetic credential marker in both
log streams, then removes its own containers and network. Python is test-only.
This is transport proof, not app authentication, Kubernetes policy enforcement,
private-network admission, real device trust or personal-vault sync proof.

Live acceptance still requires privately recorded exact object/image identities,
certificate trust on real devices, two-device encrypted sync using test notes,
application-auth denial, intended private-path connectivity and refusal of
unapproved peers, plus restart/reconnect and sizing observations. Do not use
personal notes until those checks pass. Any destructive or disruptive campaign
needs its own bounded authorization; this runbook does not supply it.
