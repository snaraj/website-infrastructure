# Issue 195 chart acquisition receipt

Captured 2026-09-01 for the issues #280/#281 drift remediation, which
advances both sites to their current published releases — naranjo.online to
`0.1.69` and lidersea.com to `0.1.41` — and supersedes the issue #268
capture of 2026-08-31. The canonical,
machine-checked record is `195-chart-acquisition-receipt.json`; this Markdown
is its explanatory view and must not be used as an independent source of
release pins. This receipt is
public, credential-free evidence for the exact two chart artifacts committed
by this repository. It is acquisition evidence, not proof of Flux or live
cluster convergence.

The operator used Cosign 3.1.3, the exact `versions.env` pin; registry reads
for the 2026-09-01 capture of both sites were direct anonymous OCI API
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
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.69` | `sha256:5a94581af2cd07465a3d4f41cc868f511af5d33ca8642812856382f41a2d8a71` / `sha256:b633abeafa8f003100f4bf428a3862a7a547e8f0eca944f111d3fc68c3f46c78` / `sha256:28f9e55716d91bce89b1db832f5ef0269c453b46a1d7d8f0911f25b4c6c73b24` | name/version/appVersion `naranjo-online` / `0.1.69` / `0.1.69` | `ghcr.io/snaraj/naranjo-online:v0.1.69@sha256:121a469347cd8915aa5441a464447fa66c17ec66635ee45a3678c7e1406810cf` | `sha256:2bc751f6483201e07b8727a22f19fea23070b6b8277b6a71a63579fc5e7cb4d5` |
| lidersea.com — `ghcr.io/snaraj/charts/lidersea-com` | `0.1.41` | `sha256:a3d242a2689c2c41a8d6960e848ea3b195ae14bc80cbf9461de36f69d4845cb6` / `sha256:ae045bde722060e04ae5f8b6c3fc4135386068026d787692c055852ade98f289` / `sha256:2c2b92acd6488afe16b1deb034e445ce3064256c1971415f8600eb601fdd09cc` | name/version/appVersion `lidersea-com` / `0.1.41` / `0.1.41` | `ghcr.io/snaraj/lidersea-com:v0.1.41@sha256:f661cdf9e33e8b36389b7f2d130a6fff6cbc1bbcb1c460968de416a831fdd86d` | `sha256:39929c6aaf5cc3c4feca57a7eac12858e83cc84505b99fdf0e0b57d6752d88e9` |

Publisher Release bindings:

- naranjo.online: protected-main source `e1647e540925b21df83d7cc13ecbb35f6d820bc4`; immutable Release asset `sha256:81f8ffddcfa98c1e9b53aa22ed156aa8a6640b9446c0adecdd1974d51007957e`.
- lidersea.com: protected-main source `382272756fafe6b7e7f52602fd6263299b5c2589`; immutable Release asset `sha256:34404bf9c348f50c0f4d0ff0a3a6efbe8b41eedf40d9ab58b1b3fa3eb4ff26d9`.

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

- naranjo `Chart.yaml`: `sha256:69e3abc46d0da16013729905f2d7095c406aee6ea5bc90f74c988bccbb926b13`
- naranjo `values.yaml`: `sha256:29578fe38d8e23158099d822462c2591b80bcb8a522df086862f39dde3b8cfdd`
- lidersea `Chart.yaml`: `sha256:5e1727720c3277fbb9d0e9be0b5994c15b1d7b1eba20cb7ae1f4e2c19c49c341`
- lidersea `values.yaml`: `sha256:c93a729c03094830ea161404ffefaeab8947f90cd0fe7568ea79506183f713b9`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
