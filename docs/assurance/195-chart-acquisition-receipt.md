# Issue 195 chart acquisition receipt

Captured 2026-09-04 for issues #302, which kept lidersea.com at `0.1.41` and
advanced naranjo.online to `0.1.73`; it supersedes the issues #285 capture of
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
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.73` | `sha256:115c9d3218393f74ba0a6e49f2587099c456b5ae6e8db154a9548ac117810a91` / `sha256:e4285d16db652036b05e51a616219e8b33b8f33b6165219d9ed3055bb7d38a8f` / `sha256:d2c043123b121f1d8fa32d15e0c5ac5890f1d7f4214c1ac6a095f4f5b614ae98` | name/version/appVersion `naranjo-online` / `0.1.73` / `0.1.73` | `ghcr.io/snaraj/naranjo-online:v0.1.73@sha256:d5e480fe1e4ccecc155e6b9adf53193541ddd820e935dabf81f1fcf81b9c44fa` | `sha256:36d2fc9bc05c804a4db0e4a51ea01a5a3f25e3c3554233b347e91fa459232593` |

Publisher Release bindings:

- lidersea.com: protected-main source `382272756fafe6b7e7f52602fd6263299b5c2589`; immutable Release asset `sha256:34404bf9c348f50c0f4d0ff0a3a6efbe8b41eedf40d9ab58b1b3fa3eb4ff26d9`.
- naranjo.online: protected-main source `a572c0a85fc0ceb464e788ba72cb0f1c943268c9`; immutable Release asset `sha256:0ab8f57ee77da992655d960bb9eec1ff1411fdcb216522839adf8bab262a3618`.

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
- naranjo `Chart.yaml`: `sha256:6b8e24aa3590a7b3e372f80bbbefc6e55329c9ae86616b72eeb5e38a30db1903`
- naranjo `values.yaml`: `sha256:5e87bbb471a703de50facb578b768fe083a808203b4b77884810608d7ac7a73e`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
