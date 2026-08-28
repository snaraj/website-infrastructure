# Issue 195 chart acquisition receipt

Captured 2026-08-27 before publishing the combined #195/#189 successor. The canonical,
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
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.50` | `sha256:22a29d488a9578d87d4a2f69fd02e4ef35daa1fb5800bc6bd12ac974b73a8c42` / `sha256:7bad4e2b48fcc166e50a6900804bfa512d21339b3d444e6938697b634f6cba4d` / `sha256:df748d25b8a4f69491f8ccce4b3d8c2b915cb41b525b5d0d80c94c780fbdf09e` | name/version/appVersion `naranjo-online` / `0.1.50` / `0.1.50` | `ghcr.io/snaraj/naranjo-online:v0.1.50@sha256:89a9e34730d32ee68338da93c8d146b315441e454aae55a70db349396295b41f` | `sha256:3b648da2b4b6c1df1232344ca16746ddb907cfcbf9b8da04da60b1253ceee361` |
| lidersea.com — `ghcr.io/snaraj/charts/lidersea-com` | `0.1.37` | `sha256:05ab03a6e7520ea6768e4efc3750c83f8f7bc827cac3289bf9ee1326c873c8fc` / `sha256:cbcc79cb9b45df8312038bee110559cf8f79588e6cf2000c7b5a1b7972afef0c` / `sha256:56a91426551dcf1e3718b37b4919d2db940199ad50e496b6e57ba385388e058c` | name/version/appVersion `lidersea-com` / `0.1.37` / `0.1.37` | `ghcr.io/snaraj/lidersea-com:v0.1.37@sha256:22673a01a892da2b644369ee3c2d0339c13ef8eddc1d3423411ce90bbe25d8b1` | `sha256:c58f87669482096362f7a4db307403f1bcee9859c643a24f23d627c08a434db4` |

Publisher Release bindings:

- naranjo.online: protected-main source `56bd0dd03f29e2300cf3553f1d4ae04a5989b127`; immutable Release asset `sha256:ed502e1a2e84eb98d71cc0a4b74a76d0274d974d89dd106e297a4a16f8ed44ef`.
- lidersea.com: protected-main source `8115ec9c277af14892b41d1f712f81fe4aab16d4`; immutable Release asset `sha256:cc1e2086d2840dcfdca8f5024234d13a92afba0b21bf9cdfbd1389dc23dbc42e`.

Each signed OCI manifest contained exactly one layer with
`application/vnd.cncf.helm.chart.content.v1.tar+gzip`; the layer selector
copies exactly that single matching layer.

Cosign accepted only these certificate subjects, with issuer
`https://token.actions.githubusercontent.com`:

- `https://github.com/snaraj/naranjo.online/.github/workflows/release-publisher.yml@refs/heads/main`
- `https://github.com/snaraj/lidersea.com/.github/workflows/release-publisher.yml@refs/heads/main`

Exact-layer inspection hashes provide a reproducible custody check:

- naranjo `Chart.yaml`: `sha256:f365f3c92099fabd452af8b6365a266c94a2e717d7caccb39783e6e72b5bec79`
- naranjo `values.yaml`: `sha256:5c2fb2b3a23bb1323a4772aab7ae8df8a97315231706e434888e1cd6c2981ec1`
- lidersea `Chart.yaml`: `sha256:84ec99f85435b09abfa10e1bdd610181ee127d8eaa34e26133c0c758743b0ce4`
- lidersea `values.yaml`: `sha256:34a22b862f6c2eb179abf911ca1b880a4d9e4d16f2f91a09483896aa0d2768c8`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
