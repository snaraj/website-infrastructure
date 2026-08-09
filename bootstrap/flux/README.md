# Flux and SOPS bootstrap — Draft / unverified

Flux reads public `main` anonymously. Do not use `flux bootstrap github` or
`flux bootstrap git`; never create a Git authentication Secret.

## Generate controllers locally

With the exact CLI in `versions.env`, run `bootstrap.sh --generate`. It exports
source-controller, kustomize-controller, and helm-controller, pins their verified
multi-arch image digests, and renders the local Kustomization. Review and
commit/push through the ordinary feature-branch workflow before cluster
bootstrap. Image-reflector and image-automation controllers remain absent.
Both apply modes also require the exact reviewed kubectl context, API URL, and
single Pi node name in `EXPECTED_KUBECONFIG_CONTEXT`,
`EXPECTED_KUBERNETES_SERVER`, and `EXPECTED_PI_NODE_NAME`; a mismatch aborts
before mutation.

## User-run age ceremony

The age private identity must never be pasted into chat or printed into logs.

1. On a trusted workstation, verify the pinned `age` and `sops` downloads and
   checksums. Start a private shell, set `umask 077`, and choose a protected
   identity location interactively so it is not entered in shell history.
2. Generate one identity with `age-keygen -o "$AGE_IDENTITY_FILE"`. Capture only
   the public `age1...` recipient. Never display or copy the identity contents.
3. Create two encrypted recovery copies in separate failure domains (for
   example, password-manager attachment and offline media). Decrypt each into a
   disposable protected file and prove it can decrypt disposable ciphertext.
4. Replace only the invalid public recipient in `.sops.yaml` and commit that
   public value.
5. Create a disposable Kubernetes Secret manifest locally and encrypt it with
   SOPS. Statically verify every `data`/`stringData` value begins with `ENC[` and
   that SOPS metadata exists. Delete disposable plaintext.
6. **Stop.** Installing the identity is an external mutation and requires an
   explicit checkpoint after controller health and backup evidence are reviewed.

At the approved checkpoint, create `sops-age` directly from the protected file
with `kubectl -n flux-system create secret generic sops-age --from-file=age.agekey="$AGE_IDENTITY_FILE"`;
do not use a command-line literal and do not pipe its YAML through logs. Then use
`bootstrap.sh --apply-sync`; it applies the two namespaces, bootstrap-owned
least-privilege access, and `gotk-sync.yaml` in that order. Flux cannot modify
its own controller or reconciliation authorization. The sync is intentionally
ordered after the age Secret so the first reconciliation does not fail
predictably.

## Tunnel token encryption

Retrieve the runtime token out of band into a mode-0600 file without printing it.
Use `kubectl -n cloudflare-public create secret generic pi-websites-tunnel-token --type=Opaque --from-file=token="$TUNNEL_TOKEN_FILE" --dry-run=client -o yaml`
as SOPS input, write only encrypted output to
`kubernetes/platform/cloudflare-public/release/tunnel-token.sops.yaml`, prove
that every `data`/`stringData` scalar is ciphertext, and delete plaintext. Never
source the token through OpenTofu state.
