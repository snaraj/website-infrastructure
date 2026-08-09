# Secret classification and handling

| Class | Examples | Repository | Runtime/backup rule |
| --- | --- | --- | --- |
| Crown-jewel | age identity, Kubernetes CA private keys, API-encryption keys, media originals, backup key, MFA recovery codes | Never; media bytes also never enter Git/OCI/etcd | encrypted, separate locations, checksummed, tested recovery |
| Infrastructure credential | Cloudflare apply/audit token, tunnel/bootstrap token, kubeconfig, SSH key | Never plaintext; tunnel token only as real SOPS ciphertext | least scope, short-lived where possible, rotate on exposure |
| Workload secret | future database/API credential | SOPS ciphertext only | one workload, stable Secret interface, rotation runbook |
| Sensitive state | OpenTofu state/plan, account/zone/tunnel IDs, home IP, topology inventory, media device/path/capacity and publication metadata | Never unless a specific encrypted design requires it | encrypt and redact before sharing |
| Public configuration | image digest, public age recipient, public hostname after launch | Allowed | integrity reviewed in Git |

Base64 is encoding, not encryption. A Kubernetes Secret with ordinary `data` or
`stringData` is rejected unless the document contains valid SOPS metadata and
ciphertext. Fake structural examples use impossible sentinel strings and are
excluded from live Kustomizations.

Never pass secrets as command-line literals where process lists or shell history
can retain them. Use protected files or supported credential inputs, do not print
values, and do not paste them into chat. Suspected disclosure means immediate
revocation/rotation and history review; deleting a current file is insufficient.
