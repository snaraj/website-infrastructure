# Secret classification and handling

| Class | Examples | Repository | Runtime/backup rule |
| --- | --- | --- | --- |
| Crown-jewel | cluster age identity, separate operator-wrapping age identity, Kubernetes CA private keys, API-encryption keys, media originals, legacy wallet/signing material and private descriptors, anonymity-service identity keys, backup key, MFA recovery codes | Never; media and legacy archive bytes also never enter Git/OCI/etcd | encrypted, separate locations, checksummed, tested recovery |
| Infrastructure credential | Cloudflare apply/audit token, tunnel/bootstrap token, kubeconfig, SSH key, VPN/WireGuard private or preshared key, legacy RPC credential/cookie | Never plaintext; tunnel token only as real SOPS ciphertext | least scope, short-lived where possible, rotate on exposure |
| Workload secret | future database/API credential | SOPS ciphertext only | one workload, stable Secret interface, rotation runbook |
| Sensitive state | OpenTofu state/plan, account/zone/tunnel IDs, home IP, topology inventory, media device/path/capacity and publication metadata, legacy archive paths/mounts/units/versions/configuration/logs/peer and wallet metadata | Never unless a specific encrypted design requires it | encrypt and redact before sharing |
| Public configuration | image digest, public age recipient, public hostname after launch | Allowed | integrity reviewed in Git |

Base64 is encoding, not encryption. A Kubernetes Secret with ordinary `data` or
`stringData` is rejected unless the document contains valid SOPS metadata and
ciphertext. Fake structural examples use impossible sentinel strings and are
excluded from live Kustomizations.
Repository validation proves only that canonical ciphertext envelopes and the
one public recipient are present. It cannot authenticate a SOPS MAC without the
private identity. A real Tunnel-token ciphertext is not approved until the
protected offline verifier decrypts it without output and matches its canonical
standard-Base64 `{a,s,t}` payload to independently reviewed account/Tunnel-ID
digests.

Never pass secrets as command-line literals where process lists or shell history
can retain them. Use protected files or supported credential inputs, do not print
values, and do not paste them into chat. Suspected disclosure means immediate
revocation/rotation and history review; deleting a current file is insufficient.

The safe Git boundary is deliberately narrow: public recipients and genuine
SOPS documents under `kubernetes/**.sops.yaml` may be committed only when all
secret payloads are ciphertext. Never commit, even under SOPS or age, either age
private identity, Cloudflare audit/apply token, the `pi-admin` token, OpenTofu
state/plan/private variables, kubeconfig/PKI/API-encryption keys, private
inventory, or recovery locations. The public `pi-websites` runtime token may be
committed only as SOPS ciphertext for its one cluster Secret and must be revoked
when the cluster identity is compromised.

A convenience archive catalog may contain only sanitized guidance, bounded
hashes, and non-sensitive references. It is not a safe destination for wallet
files, seeds, descriptors, RPC material, anonymity identities, VPN profiles, or
private keys. Those require operator-controlled encrypted off-device copies and
a restore test whose shareable result is only `PASS` or `FAIL`.
