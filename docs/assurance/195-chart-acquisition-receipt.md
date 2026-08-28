# Issue 195 chart acquisition receipt

Captured 2026-08-28 before publishing the combined #195/#189 successor. The canonical,
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
| naranjo.online — `ghcr.io/snaraj/charts/naranjo-online` | `0.1.54` | `sha256:7223dd78f308c1e211da71f6e062195724aaedc47962b0a04907eeb0baf2d7bb` / `sha256:34336fc8887ca9d4e540674d85f726d830974cb8f909f5202b9bd58a7f85a609` / `sha256:56d37664cfedcddafcc9bd440b69e27b1f386012b9fe55868dd7d0e8d773a494` | name/version/appVersion `naranjo-online` / `0.1.54` / `0.1.54` | `ghcr.io/snaraj/naranjo-online:v0.1.54@sha256:8f3eeac4caa0bbc8c88f1e9725e9eeb7e074ece3f7c53a77ada52fea28667c78` | `sha256:3a4477a4d983487e2b9d0aee8b556502d9db3fc56b72d0bc111eb83bb71fc5c3` |
| lidersea.com — `ghcr.io/snaraj/charts/lidersea-com` | `0.1.37` | `sha256:05ab03a6e7520ea6768e4efc3750c83f8f7bc827cac3289bf9ee1326c873c8fc` / `sha256:cbcc79cb9b45df8312038bee110559cf8f79588e6cf2000c7b5a1b7972afef0c` / `sha256:56a91426551dcf1e3718b37b4919d2db940199ad50e496b6e57ba385388e058c` | name/version/appVersion `lidersea-com` / `0.1.37` / `0.1.37` | `ghcr.io/snaraj/lidersea-com:v0.1.37@sha256:22673a01a892da2b644369ee3c2d0339c13ef8eddc1d3423411ce90bbe25d8b1` | `sha256:c58f87669482096362f7a4db307403f1bcee9859c643a24f23d627c08a434db4` |

Publisher Release bindings:

- naranjo.online: protected-main source `0438570c8f0ccb40ceb0869b86cb461823c8c447`; immutable Release asset `sha256:2568aca870eff2495d217afbdd933389d2236552c704bb83b321201db7081599`.
- lidersea.com: protected-main source `8115ec9c277af14892b41d1f712f81fe4aab16d4`; immutable Release asset `sha256:cc1e2086d2840dcfdca8f5024234d13a92afba0b21bf9cdfbd1389dc23dbc42e`.

Each signed OCI manifest contained exactly one layer with
`application/vnd.cncf.helm.chart.content.v1.tar+gzip`; the layer selector
copies exactly that single matching layer.

Cosign accepted only these certificate subjects, with issuer
`https://token.actions.githubusercontent.com`:

- `https://github.com/snaraj/naranjo.online/.github/workflows/release-publisher.yml@refs/heads/main`
- `https://github.com/snaraj/lidersea.com/.github/workflows/release-publisher.yml@refs/heads/main`

Exact-layer inspection hashes provide a reproducible custody check:

- naranjo `Chart.yaml`: `sha256:3114f08f179c83043a9eb43f4694fd5ad7673d8b73593d14eb1e8ddfc18c4c6e`
- naranjo `values.yaml`: `sha256:f155102a52bf1dfe7be161aeba24b450b04ab39a24c260a300ef04bffd4ae068`
- lidersea `Chart.yaml`: `sha256:84ec99f85435b09abfa10e1bdd610181ee127d8eaa34e26133c0c758743b0ce4`
- lidersea `values.yaml`: `sha256:34a22b862f6c2eb179abf911ca1b880a4d9e4d16f2f91a09483896aa0d2768c8`

Future updates repeat this exact sequence: resolve the reviewed tag, verify the
exact manifest, config, sole layer and signer, inspect chart identity and
embedded workload image, bind the protected source and immutable Release
asset, resolve the tag again, then atomically review the audit annotation and
digest. Tag movement, deletion, or replacement after that point cannot change
the bytes selected by the committed digest.
