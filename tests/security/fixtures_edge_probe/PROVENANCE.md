# edge-probe parser fixtures — provenance

Every file here is a **real capture**, taken on 2026-08-12 with OpenSSL 3.6.3
and DiG 9.10.6, not a hand-written approximation. That matters: the two defects
these fixtures pin were both invisible to a plausible hand-written sample, and
a hand-written fixture would have let the defective parser pass.

| Fixture | Command | Pins |
|---|---|---|
| `tls13-remote-success.txt` | `echo \| openssl s_client -connect <apex>:443 -servername <apex> -tls1_3` | A successful TLS 1.3 handshake that prints **no `SSL-Session:` block**. The attestation's §9.2 parser keyed on the indented `Protocol  :` line inside that block and reported HANDSHAKE-FAILED for this exact transcript. |
| `tls10-refused-by-server.txt` | `openssl s_client -tls1` against a loopback `s_server -tls1_2` (server refuses) | A **refused** handshake that nevertheless prints `Protocol: TLSv1` next to `New, (NONE), Cipher is (NONE)`, and carries a full `SSL-Session:` block with an indented `Protocol  : TLSv1`. A parser keyed on either `Protocol` line reports this refusal as an acceptance — the mirror-image false PASS. |
| `client-cannot-attempt.txt` | `openssl s_client -ssl3` | The local client cannot attempt the protocol at all. This must never be reported as a server verdict. |
| `early-data-zero.txt` | `printf 'HEAD / …' \| openssl s_client -tls1_3 -ign_eof` | Post-handshake session tickets carrying `Max Early Data: 0` — 0-RTT off, as a positive observation. |
| `early-data-truncated-probe.txt` | `echo \| openssl s_client -tls1_3` | The truncated-probe defect: stdin closes before any ticket arrives, so no `Max Early Data` line exists. This is a SKIP, never a pass. |
| `dig-www-signed-zone-nodata.txt` | `dig @<resolver> A www.<signed apex> +noall +comments` | `NOERROR` / `ANSWER: 0` — how a DNSSEC-signed Cloudflare zone denies a nonexistent name. Treating it as anything but absence is a false positive on the signed zone only. |
| `dig-www-unsigned-zone-nxdomain.txt` | `dig @<resolver> A www.<unsigned apex> +noall +comments` | `NXDOMAIN` — the same absence on an unsigned zone. |
| `dig-name-present.txt` | `dig @<resolver> NS <apex> +noall +comments` | `NOERROR` with `ANSWER: 2` — a name that **does** exist, so the absence check cannot be vacuous. |

## Exactly what was edited, and why

The captures are verbatim except for the substitutions below, each of which
exists because the repository privacy and secret gates apply to every tracked
byte. None of them touches a line any parser reads.

1. `Connecting to <address>` → `Connecting to 192.0.2.1` (RFC 5737
   documentation address). The real value is a Cloudflare anycast address; the
   privacy gate rejects address literals outside its documentation allowlist.
2. The certificate PEM block → `[certificate PEM elided]`. Bulk base64 with no
   test value.
3. `Session-ID`, `Session-ID-ctx`, `Master-Key`, `Resumption PSK` values and
   the `TLS session ticket:` hex dump → `[value elided]` / `[ticket bytes
   elided]`. Ephemeral key material never belongs in Git, expired or not.
4. `Date`, `CF-RAY`, `Server-Timing`, `Report-To` and `Nel` response headers →
   `[value elided]`. Per-request identifiers and an opaque reporting endpoint
   token.

The `dig` captures use `+noall +comments`, which prints the header and flag
lines the parser reads and no address records or `;; SERVER:` line, so they
needed no editing at all.
