# Secret classification and handling

| Class | Examples | Repository | Runtime/backup rule |
| --- | --- | --- | --- |
| Crown-jewel | operator-wrapping age identity, Kubernetes CA private keys, API-encryption keys, media originals, legacy wallet/signing material and private descriptors, anonymity-service identity keys, backup key, MFA recovery codes | Never; media and legacy archive bytes also never enter Git/OCI/etcd | encrypted, separate locations, checksummed, tested recovery |
| Infrastructure credential | Cloudflare apply/audit token, tunnel/bootstrap token, kubeconfig, SSH key, VPN/WireGuard private or preshared key, legacy RPC credential/cookie | Never | least scope, short-lived where possible, rotate on exposure |
| Workload secret | future database/API credential | Never | one workload, stable Secret interface, rotation runbook |
| Sensitive state | OpenTofu state/plan, account/zone/tunnel IDs, home IP, topology inventory, media device/path/capacity and publication metadata, legacy archive paths/mounts/units/versions/configuration/logs/peer and wallet metadata | Never unless a specific encrypted design requires it | encrypt and redact before sharing |
| Public configuration | image digest, public hostname after launch | Allowed | integrity reviewed in Git |

Base64 is encoding, not encryption, and encryption is not an exemption: this
repository commits no Kubernetes Secret at all. Every runtime Secret is created
on the cluster by an owner ceremony. Fake structural examples use impossible
sentinel strings and are excluded from live Kustomizations.

Never pass secrets as command-line literals where process lists or shell history
can retain them. Use protected files or supported credential inputs, do not print
values, and do not paste them into chat. Suspected disclosure means immediate
revocation/rotation and history review; deleting a current file is insufficient.

The safe Git boundary is deliberately narrow: no secret payload of any class
is committed, in any encoding. Never commit an age private identity, the
Cloudflare audit/apply token, the `pi-admin` token, the `pi-websites` runtime
token, OpenTofu state/plan/private variables, kubeconfig/PKI/API-encryption
keys, private inventory, or recovery locations.

A convenience archive catalog may contain only sanitized guidance, bounded
hashes, and non-sensitive references. It is not a safe destination for wallet
files, seeds, descriptors, RPC material, anonymity identities, VPN profiles, or
private keys. Those require operator-controlled encrypted off-device copies and
a restore test whose shareable result is only `PASS` or `FAIL`.
