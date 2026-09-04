# Issue 195 chart acquisition receipt

Captured 2026-09-04 for issues #302, which kept lidersea.com at `0.1.41` and
advanced naranjo.online to `0.1.72`; it supersedes the issues #285 capture of
2026-09-01. The canonical, machine-checked record is
`195-chart-acquisition-receipt.json`; this Markdown is its explanatory view
and must not be used as an independent source of release pins. This receipt
is public, credential-free evidence for the exact chart artifacts committed
by this repository. It is acquisition evidence, not proof of Flux or live
cluster convergence.

The acquisition was run by `scripts/promote_releases.py` with Cosign 3.1.3,
the exact `versions.env` pin; registry reads were direct anonymous OCI API
resolutions whose `docker-content-digest` answers were required to agree with
the fetched manifest bytes' own hashes (the technique reviewed in PRs #255 and
#259), with ORAS 1.3.3 remaining the pinned acquisition tool of record.
Each human tag was resolved, the resulting repository-at-digest was
verified against the exact publisher identity and GitHub Actions issuer, the
Helm layer was fetched by its own digest and inspected, and both chart and
embedded workload tags were resolved a second time. Both pairs of resolutions
agreed. The immutable Release asset and protected-main source commit were
also bound for each acquisition. Public SLSA v1 attestations bound the exact
workload indexes; chart trust remains each chart's exact Cosign signature.

| workload and canonical chart repository | tag | OCI manifest / config / chart-layer digests | Chart.yaml identity | embedded workload image | Linux ARM64 child |
| --- | --- | --- | --- | --- | --- |
| lidersea.com — `ghcr.io/snaraj/charts/lidersea-com` | `0.1.41` | `sha256:a3d242a2689c2c41a8d6960e848ea3b195ae14bc80cbf9461de36f69d4845cb6` / `sha256:ae045bde722060e04ae5f8b6c3fc4135386068026d787692c055852ade98f289` / `sha256:2c2b92acd6488afe16b1deb034e445ce3064256c1971415f8600eb601fdd09cc` | name/version/appVersion `lidersea-com` / `0.1.41` / `0.1.41` | `ghcr.io/snaraj/lidersea-com:v0.1.41@sha256:f661cdf9e33e8b36389b7f2d130a6fff6cbc1bbcb1c460968de416a831fdd86d` | `sha256:39929c6aaf5cc3c4feca57a7eac12858e83cc84505b99fdf0e0b57d6752d88e9` |
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.72` | `sha256:c7be31f0a27f352018c6e58f41f4e4f08be382619976085883674972dca471ec` / `sha256:bf141d187c2d501abe2a2a8bbfc5b83706f58b3ef93e41fe183795865191880c` / `sha256:6a99f8d924863a17612a5aa6cd169bd820cb23c79f6136709f655967dc565980` | name/version/appVersion `naranjo-online` / `0.1.72` / `0.1.72` | `ghcr.io/snaraj/naranjo-online:v0.1.72@sha256:3a9b31dd3d47ed80aeb592e967c7343d852aae15f570a139eeecf6432a634203` | `sha256:195950ff575d571cf244ffdd4f55b7ba53fe2fa4a53b5784335c931af82f462a` |

Publisher Release bindings:

- lidersea.com: protected-main source `382272756fafe6b7e7f52602fd6263299b5c2589`; immutable Release asset `sha256:34404bf9c348f50c0f4d0ff0a3a6efbe8b41eedf40d9ab58b1b3fa3eb4ff26d9`.
- naranjo.online: protected-main source `3a4631797c78d55db7799fb8e22f42e364cad7ee`; immutable Release asset `sha256:925d657613f52365a776ae14d16a517529d040fbcf48a7bff371c1fb5433233a`.

Each `vX.Y.Z` annotated tag was dereferenced to the commit above, and that
same commit is what the Release asset's own `source_sha` field reports — two
independent statements of the source binding that had to agree. Each manifest
also states the chart and image digests independently of the registry
resolution, and both agreed.

Each signed OCI manifest contained exactly one layer with
`application/vnd.cncf.helm.chart.content.v1.tar+gzip`; the layer selector
copies exactly that single matching layer.

Cosign accepted only these certificate subjects, with issuer
`https://token.actions.githubusercontent.com`:

- `https://github.com/snaraj/lidersea.com/.github/workflows/release-publisher.yml@refs/heads/main`
- `https://github.com/snaraj/naranjo.online/.github/workflows/release-publisher.yml@refs/heads/main`

Exact-layer inspection hashes provide a reproducible custody check:

- lidersea `Chart.yaml`: `sha256:5e1727720c3277fbb9d0e9be0b5994c15b1d7b1eba20cb7ae1f4e2c19c49c341`
- lidersea `values.yaml`: `sha256:c93a729c03094830ea161404ffefaeab8947f90cd0fe7568ea79506183f713b9`
- naranjo `Chart.yaml`: `sha256:e30f28f6a7abf705f290c7afcf41db07a8421d5b8748b51c4982a31079406f03`
- naranjo `values.yaml`: `sha256:e7ef6ee7ee78492ebb060b17cdc0d4e35ebc46c8626904761d5af37d18e9e376`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
