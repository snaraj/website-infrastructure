# Issue 195 chart acquisition receipt

Captured 2026-08-29 for the issue #252 forward selection, which advances both
sites to their published releases (naranjo.online `0.1.60`, lidersea.com
`0.1.40`) and supersedes the 2026-08-28 capture. The canonical,
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
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.60` | `sha256:0c67bf604e25ddba0f5e2c43036884456d29137b153af22d8cb7c640628199c6` / `sha256:d6a022f3e905f9591f0c963925877b4cc878a4201eb2d46cc1dae0dff033228c` / `sha256:a24ee5b9e4e644e0ff7ccccf916f2f86c37279c5f9448ba4cbb059907d60c166` | name/version/appVersion `naranjo-online` / `0.1.60` / `0.1.60` | `ghcr.io/snaraj/naranjo-online:v0.1.60@sha256:f9b9570396bfd4a555db8290cd71580136436c4c53e021a09a8317718cfe7e1f` | `sha256:8f6ac1279083790ffbf8a46f57ba81364919edd8ee9e787126bb2cf2cb2efe1b` |
| lidersea.com — `ghcr.io/snaraj/charts/lidersea-com` | `0.1.40` | `sha256:004eaecfcc3dbbe2693e4c400be3dbf755a7972d40b7a5b5755b64e10afb354b` / `sha256:bfeeb2bb371448f552e52ebdc1a0576f5f016e6421286315b4220ba8fb0a9c53` / `sha256:578296a596d8835a0e9185e46d6b2ac111ff19c181890e83b44d2caec0b4e517` | name/version/appVersion `lidersea-com` / `0.1.40` / `0.1.40` | `ghcr.io/snaraj/lidersea-com:v0.1.40@sha256:cf8dfc93c863296c7de42ec92850a68ab173417d87498f315fafaec9864484c0` | `sha256:694663936ee1061df4a74c19d6f3b5caa22892225dc776587e83721b7488840d` |

Publisher Release bindings:

- naranjo.online: protected-main source `f93144e0b4cca016d6362a00a0a862747aeb5eb8`; immutable Release asset `sha256:f01aded3cefb24d88c72e8fe5d094c7e56a3c0ece657c75a2b11f04def1e07b0`.
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

- naranjo `Chart.yaml`: `sha256:c4eaf528d1f3f26257e768cf05c8d927c815d450ee0d447d7674052fcff65596`
- naranjo `values.yaml`: `sha256:9863552d4226005067a51ed84c4e9f4f43324a91d6f74b71fc6be9215fa5ad1c`
- lidersea `Chart.yaml`: `sha256:60dc172458da049d5c074f9d07fce02d4f340480ceb32d383ed41be218dc2816`
- lidersea `values.yaml`: `sha256:9a96dabb40f480ca8c4b47304738476bd47ebe1de7945c8f5795502396245cc5`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
