# Trust boundaries

| Boundary | May initiate | Explicitly denied |
| --- | --- | --- |
| Internet visitor | HTTPS through approved Cloudflare hostname | Origin, SSH, Kubernetes API |
| `pi-websites` connector | DNS, Cloudflare Tunnel transport, approved site TCP 8080 | Pi host, admin route, Kubernetes API, arbitrary egress |
| `naranjo-online` pod | Serve `naranjo.online` on TCP 8080 after connector ingress | All egress, API token, other namespaces, host |
| `lidersea-com` pod | Serve `lidersea.com` on TCP 8080 after connector ingress | All egress, API token, other namespaces, host |
| Future naranjo media reader | Read single-link regular delivery derivatives through one rooted, read-only, mount-verified boundary | Originals, staging, metadata, links, nested mounts, writes, directory listing, other host paths |
| Media operator | Stage, checksum, derive, atomically publish, back up, and restore through the protected path | Public upload API, in-place publication, anonymous writes, runtime transcoding |
| Legacy archive operator | Preserve and verify an explicitly declared inactive archive through the protected local path | Runtime activation, public/Tunnel route, Kubernetes/Flux/CI access, broad filesystem operations, secret disclosure |
| Flux source controller | Anonymous HTTPS Git fetch | Git write, deploy keys, cluster-wide tenant mutation |
| Tenant reconciler | Named namespace resources | Other namespaces and cluster-scoped privilege |
| Admin laptop | TCP 22/6443 after identity/device policy | Other Pi traffic and WARP-off remote access |
| Local OpenTofu operator | Reviewed allowlisted Cloudflare changes | Billing/Registrar write, subscriptions, unknown products |

Namespaces `cloudflare-public`, `naranjo-online`, and `lidersea-com` are separate
policy and quota boundaries. Kubernetes namespace is not the only control:
RBAC, NetworkPolicy, Pod Security, image policy, and separate credentials are
all required. A future PersistentVolume is cluster-scoped and therefore needs
separate admission/RBAC review; a PVC is not proof that its backing path or
mount is safe.

The protected legacy archive is not a namespace or storage class. Its exact
units, roots, mount binding, identities, and evidence remain outside Git and are
denied to Flux, Pods, both Tunnel connectors, CI, and provider tooling. A future
restore requires a new isolated trust boundary and threat-model decision; a
cluster rebuild or ordinary rollback may not activate it.

The Cloudflare service boundary is also a trust and entitlement boundary. A
proxied Tunnel CNAME does not become a direct origin when a response bypasses
cache. Current self-serve terms are incompatible with deliberate heavy-media
delivery under this repository's zero-spend constraint, so no enabled storage
profile or public large-media route may cross it.
