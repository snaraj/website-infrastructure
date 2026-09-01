# Issue 195 chart acquisition receipt

Captured 2026-08-31 for the issue #268 forward selection, which advances
naranjo.online alone to its published release `0.1.66` and supersedes the
issue #258 capture of 2026-08-29; the lidersea.com `0.1.40` record carries
forward from that capture unchanged. The canonical,
machine-checked record is `195-chart-acquisition-receipt.json`; this Markdown
is its explanatory view and must not be used as an independent source of
release pins. This receipt is
public, credential-free evidence for the exact two chart artifacts committed
by this repository. It is acquisition evidence, not proof of Flux or live
cluster convergence.

The operator used Cosign 3.1.3, the exact `versions.env` pin; registry reads
for the 2026-08-31 naranjo.online capture were direct anonymous OCI API
resolutions whose `docker-content-digest` answers were required to agree with
the fetched manifest bytes' own hashes (the technique reviewed in PRs #255 and
#259), with ORAS 1.3.3 remaining the pinned acquisition tool of record.
Each human tag was resolved, the resulting repository-at-digest was
verified against the exact site publisher identity and GitHub Actions issuer,
the Helm layer was fetched by its own digest and inspected, and both chart and
embedded workload tags were resolved a second time. Both pairs of resolutions
agreed. The immutable site Release asset and protected-main source commit were
also bound for each acquisition. Public SLSA v1 attestations bound the exact
workload indexes; chart trust remains each chart's exact Cosign signature.

| site and canonical chart repository | tag | OCI manifest / config / chart-layer digests | Chart.yaml identity | embedded workload image | Linux ARM64 child |
| --- | --- | --- | --- | --- | --- |
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.66` | `sha256:0d89ce68c5aa1413e436e84d39358444b8180238e81a701248c65fabfe1d26e1` / `sha256:6dbf80f2c75e5686fe7d569ecf70ef4d20dd2467b3539702c9353844345fc365` / `sha256:38074e0210c1ff7fdf27d18544d26aec7153d31870b4e30288b6697cb15b57ea` | name/version/appVersion `naranjo-online` / `0.1.66` / `0.1.66` | `ghcr.io/snaraj/naranjo-online:v0.1.66@sha256:e8af1f3f036f164c637cc9fc76d3e9e6406736d1ce75fc0bf7499786adc68258` | `sha256:0818dcb06c930843aaf23b0d32f07322ab9afe45d9de8526ffedb70a3ebf9454` |
| lidersea.com — `ghcr.io/snaraj/charts/lidersea-com` | `0.1.40` | `sha256:004eaecfcc3dbbe2693e4c400be3dbf755a7972d40b7a5b5755b64e10afb354b` / `sha256:bfeeb2bb371448f552e52ebdc1a0576f5f016e6421286315b4220ba8fb0a9c53` / `sha256:578296a596d8835a0e9185e46d6b2ac111ff19c181890e83b44d2caec0b4e517` | name/version/appVersion `lidersea-com` / `0.1.40` / `0.1.40` | `ghcr.io/snaraj/lidersea-com:v0.1.40@sha256:cf8dfc93c863296c7de42ec92850a68ab173417d87498f315fafaec9864484c0` | `sha256:694663936ee1061df4a74c19d6f3b5caa22892225dc776587e83721b7488840d` |

Publisher Release bindings:

- naranjo.online: protected-main source `2e48af561f07409762bc7df7b38daa7306893dd9`; immutable Release asset `sha256:dbe446315b1036560ea68aaa2423bc1c93469dd4e022b698667897cfa7a49d5b`.
- lidersea.com: protected-main source `54790ce20cbe032bedcf12432001b754615b2f56`; immutable Release asset `sha256:c6d3571e10fda52ea9472e8f328f97892408dcaccbb237aa40d7b2d33a5eb771`.

Each site's `vX.Y.Z` annotated tag was dereferenced to the commit above, and
that same commit is what the Release asset's own `source_sha` field reports —
two independent statements of the source binding that had to agree. Each
manifest also states the chart and image digests independently of the registry
resolution, and both agreed.

Each signed OCI manifest contained exactly one layer with
`application/vnd.cncf.helm.chart.content.v1.tar+gzip`; the layer selector
copies exactly that single matching layer.

Cosign accepted only these certificate subjects, with issuer
`https://token.actions.githubusercontent.com`:

- `https://github.com/snaraj/naranjo.online/.github/workflows/release-publisher.yml@refs/heads/main`
- `https://github.com/snaraj/lidersea.com/.github/workflows/release-publisher.yml@refs/heads/main`

Exact-layer inspection hashes provide a reproducible custody check:

- naranjo `Chart.yaml`: `sha256:cdef9a64eb7801b1a5661533978e886bcd1608456ebd08b9b9938af367b4fb18`
- naranjo `values.yaml`: `sha256:323b2860cbdd867ece07d1facdbc772e5bcafda4210a1ec724426156b91acbcb`
- lidersea `Chart.yaml`: `sha256:60dc172458da049d5c074f9d07fce02d4f340480ceb32d383ed41be218dc2816`
- lidersea `values.yaml`: `sha256:9a96dabb40f480ca8c4b47304738476bd47ebe1de7945c8f5795502396245cc5`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
