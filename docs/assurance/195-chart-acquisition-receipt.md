# Issue 195 chart acquisition receipt

Captured 2026-08-29 for the issue #258 forward selection, which advances
naranjo.online alone to its published release `0.1.63` and supersedes the
issue #254 capture of the same day; the lidersea.com `0.1.40` record carries
forward from that capture unchanged. The canonical,
machine-checked record is `195-chart-acquisition-receipt.json`; this Markdown
is its explanatory view and must not be used as an independent source of
release pins. This receipt is
public, credential-free evidence for the exact two chart artifacts committed
by this repository. It is acquisition evidence, not proof of Flux or live
cluster convergence.

The operator used the versions pinned by `versions.env`: ORAS 1.3.3 and Cosign
3.1.3. Each human tag was resolved, the resulting repository-at-digest was
verified against the exact site publisher identity and GitHub Actions issuer,
the Helm layer was fetched by its own digest and inspected, and both chart and
embedded workload tags were resolved a second time. Both pairs of resolutions
agreed. The immutable site Release asset and protected-main source commit were
also bound for each acquisition. Public SLSA v1 attestations bound the exact
workload indexes; chart trust remains each chart's exact Cosign signature.

| site and canonical chart repository | tag | OCI manifest / config / chart-layer digests | Chart.yaml identity | embedded workload image | Linux ARM64 child |
| --- | --- | --- | --- | --- | --- |
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.63` | `sha256:ee0b471a8d03e7163a485931b273663938851efcb6af595c7102ce76e3726d0d` / `sha256:36f22f2cdd60a16a2c047b603f273e1eac5ac08470cc401609379fbb6a535744` / `sha256:03d994b7767a4b94765137a68f605d8371ab310c89f84868161b69cf4729d062` | name/version/appVersion `naranjo-online` / `0.1.63` / `0.1.63` | `ghcr.io/snaraj/naranjo-online:v0.1.63@sha256:412719b2a8ec9570c5856948512629d3e15a669841c26bb03b45d7e7d757a2bc` | `sha256:8da8da5e8bc0f0c372ef9598a0ec9024fffd253f957b01621c939ff0466ba6d4` |
| lidersea.com — `ghcr.io/snaraj/charts/lidersea-com` | `0.1.40` | `sha256:004eaecfcc3dbbe2693e4c400be3dbf755a7972d40b7a5b5755b64e10afb354b` / `sha256:bfeeb2bb371448f552e52ebdc1a0576f5f016e6421286315b4220ba8fb0a9c53` / `sha256:578296a596d8835a0e9185e46d6b2ac111ff19c181890e83b44d2caec0b4e517` | name/version/appVersion `lidersea-com` / `0.1.40` / `0.1.40` | `ghcr.io/snaraj/lidersea-com:v0.1.40@sha256:cf8dfc93c863296c7de42ec92850a68ab173417d87498f315fafaec9864484c0` | `sha256:694663936ee1061df4a74c19d6f3b5caa22892225dc776587e83721b7488840d` |

Publisher Release bindings:

- naranjo.online: protected-main source `ef75165997f392027f2d9e085a0b5c199b1521bd`; immutable Release asset `sha256:917f5a3e339fd2f825d6e633522d69bc3447f4f9e9ec0947890052482a7f7cef`.
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

- naranjo `Chart.yaml`: `sha256:9308a1b6e78e02996f3d8f581576973c2da4e7f0237a6179821a739bb7df2322`
- naranjo `values.yaml`: `sha256:b65c79d8e80c5bfbc50828a5dc4d0a51e0d5f5fcdb6367e1d4926a6439746d01`
- lidersea `Chart.yaml`: `sha256:60dc172458da049d5c074f9d07fce02d4f340480ceb32d383ed41be218dc2816`
- lidersea `values.yaml`: `sha256:9a96dabb40f480ca8c4b47304738476bd47ebe1de7945c8f5795502396245cc5`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
