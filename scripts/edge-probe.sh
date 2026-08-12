#!/usr/bin/env bash
# Token-free, read-only acceptance probe for the two public site edges.
#
# WHAT THIS IS. A credential-free external observer. It reads only what any
# internet client can read from the two public hostnames plus two public DNS
# resolvers, compares each observation against the encoded target state, and
# prints PASS / GAP / SKIP / RECORD per item. It contacts nothing else: no
# Cloudflare API, no cluster, no SSH, no third-party scanner or rating
# service, no telemetry. It never takes, reads, or emits a credential.
#
# WHAT IT IS NOT. It does not duplicate scripts/verify-exposure.sh, which is
# the exposure gate (exact tenant identity, unexpected-hostname denial,
# residential-origin port closure) and needs operator-supplied private inputs.
# It does not read Cloudflare configuration: every verdict here is a statement
# about observable behaviour, never about which knob produced it. Configuration
# truth needs the owner-run authenticated reader
# (scripts/cloudflare-account-audit.sh).
#
# DEFAULT IS REPORT-ONLY. The probe is designed to be useful BEFORE the target
# state is reached: it exits 0 while reporting GAPs so it can be run against
# today's edge, and only --enforce turns an unmet target into a nonzero exit.
#
# METHOD DEFECTS THIS SCRIPT IS BUILT TO AVOID. Every rule below was learned
# from a failed probe during the 2026-08-12 edge attestation; the referenced
# sections are that attestation's:
#
#   1. Capability preflight before any legacy-TLS claim (§12 tier 3). OpenSSL
#      3.x refuses TLS < 1.2 client-side at its default security level, so a
#      naive `-tls1` probe fails and reads exactly like a server that rejects
#      TLS 1.0. This script proves the local stack can speak each protocol
#      against a local s_server first, and emits a loud SKIP — never a PASS or
#      a GAP — for any protocol the client cannot speak. A client limitation is
#      never reported as a server result.
#   2. TLS results are parsed from the UNINDENTED `Protocol:` and `New, TLSv`
#      lines (§9.2, §12 rule 1). The indented `    Protocol  :` line inside the
#      `SSL-Session:` block is absent for a TLS 1.3 connection that closes
#      before a session is established; a parser keyed on it reported
#      HANDSHAKE-FAILED for a handshake that had plainly succeeded.
#   3. 0-RTT is read from `Max Early Data:` on the post-handshake session
#      tickets, and the connection is fed a real HEAD request with -ign_eof
#      (§9 divergence 1, §12 rule 6). `echo |` closes stdin before any ticket
#      arrives and yields a false "no ticket".
#   4. grep is invoked through an absolute path and every pattern is passed
#      with -e (§10, §12 rule 2). An interactive shell shimming grep to ugrep
#      parses a `-`-leading pattern as an option and silently returns nothing.
#   5. No dependency on timeout(1)/gtimeout(1) (§10, §12 rule 3) — absent on
#      the operator host. curl is bounded with --max-time and openssl through
#      this script's own dependency-free watchdog.
#   6. Distinctness is asserted on <title> and asset filenames, NEVER on a
#      whole-body hash (Cloudflare injects a per-request ray ID into every HTML
#      response, so the hash differs between two identical rounds) and NEVER on
#      <h1> (identical on both sites — a vacuous assertion). §7.1, §12 rule 5.
#   7. "Name does not exist" accepts NXDOMAIN or NOERROR/ANSWER:0 (§8, §12
#      rule 7). A DNSSEC-signed Cloudflare zone never returns NXDOMAIN; it
#      answers NOERROR/NODATA with a synthesized NSEC ("black lies"). Treating
#      that as a failure would be a false positive on the signed zone only.
#   8. Every probe runs twice by default and disagreeing rounds are reported as
#      DIVERGENT rather than silently taking the last result (§7, §9).
#
# PUBLIC RESOLVERS ARE ADDRESSED BY NAME, not by IPv4 literal, because the
# repository privacy gate (scripts/validate_repository.py privacy) rejects
# address literals outside its documentation allowlist in tracked text. The
# names below are the operators' own canonical public names for the same
# service; nothing about the check is weakened by using them.
set -Eeuo pipefail
set +x

readonly SCHEMA='edge-probe/1'
# The two public site identities. Fixed on purpose: this probe accepts no
# alternate hostname, so it can never be pointed at a third party.
readonly ZONE_A='naranjo.online'
readonly ZONE_B='lidersea.com'
# Encoded per-zone DNSSEC expectation. naranjo.online is signed and validating;
# lidersea.com is unsigned pending the owner's signing ceremony, so "unsigned"
# is that zone's expected state today and is reported as PASS with the pending
# ceremony recorded separately as dnssec-parity.
readonly ZONE_A_DNSSEC='signed'
readonly ZONE_B_DNSSEC='unsigned'
# Two independent validating resolvers, addressed by name (see header).
readonly RESOLVER_ONE='one.one.one.one'
readonly RESOLVER_TWO='dns.google'
# The exact target value. Anything beyond max-age (includeSubDomains, preload)
# is deliberately NOT the target state in this phase.
readonly HSTS_TARGET='max-age=31536000'
# Certificate renewal headroom. Cloudflare renews Universal SSL automatically;
# this is a monitoring threshold, not a policy.
readonly CERT_MIN_DAYS=21
readonly SECURITY_HEADERS='content-security-policy x-content-type-options referrer-policy permissions-policy x-frame-options cross-origin-resource-policy'

# grep is resolved once, absolutely, at load time: every pattern in this file
# is additionally passed with -e so a shimmed grep cannot eat a leading dash.
resolve_grep() {
  local candidate
  for candidate in /usr/bin/grep /bin/grep; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  command -v grep
}
GREP="$(resolve_grep)"
readonly GREP

OPENSSL=''
OPENSSL_IS_THREE=no
CURL=''
DIG=''
WORKDIR=''
RECORDS=''
ROUNDS=2
ROUND_GAP=5
TIMEOUT=25
ENFORCE=no
ZONES=''
PREFLIGHT_TLS1=unknown
PREFLIGHT_TLS1_1=unknown
PREFLIGHT_TLS1_2=unknown
PREFLIGHT_TLS1_3=unknown

usage() {
  cat <<'USAGE'
Usage:
  scripts/edge-probe.sh [--enforce] [--zone HOSTNAME] [--rounds N]
                        [--round-gap SECONDS] [--timeout SECONDS]
  scripts/edge-probe.sh --self-test
  scripts/edge-probe.sh --help

Read-only, credential-free acceptance probe for the two public site edges.
It contacts only the site hostnames and two public DNS resolvers.

Options:
  --enforce           Exit nonzero unless every APPLICABLE asserted item is
                      PASS. An unproven target (SKIP), a disagreement between
                      rounds (DIVERGENT) and a probe error all fail under
                      --enforce: an item that could not be proven is never a
                      pass. An item outside the selected scope is reported
                      INAPPLICABLE and does not fail -- inapplicable is not
                      the same as unproven. Without --enforce the probe is
                      report-only and exits 0 whatever it finds, so it is
                      useful before the target state is reached.
  --zone HOSTNAME     Probe one site only (naranjo.online or lidersea.com).
                      Cross-zone distinctness is then INAPPLICABLE, so a
                      single-zone --enforce run still exits 0 when that zone
                      meets the target state.
  --rounds N          Repetitions, 1-5 (default 2). Disagreeing rounds are
                      reported as DIVERGENT, never silently resolved.
  --round-gap SECONDS Pause between rounds, 0-600 (default 5).
  --timeout SECONDS   Per-request bound, 5-120 (default 25). No dependency on
                      timeout(1), which is absent on the operator host.
  --self-test         Prove the local TLS client capability matrix and the
                      transcript parsers offline. Contacts no remote host.
  --help              This text.

Target state asserted (attestation 2026-08-12, ADR 0015):
  HTTP -> HTTPS       exactly one 30x preserving path and query
  minimum TLS         1.2 (TLS 1.0 and 1.1 refused, 1.2 and 1.3 accepted)
  0-RTT               off (Max Early Data: 0 on every session ticket)
  HSTS                exactly max-age=31536000 (no includeSubDomains/preload)
  DNSSEC              naranjo.online signed and validating; lidersea.com
                      unsigned until the owner's signing ceremony
  /readyz             200
  www.<apex>          absent (NXDOMAIN, or NOERROR/NODATA on the signed zone)
  identity            each apex serves its own <title> and its own assets

Exit codes: 0 ok, 1 unmet target under --enforce, 2 usage or tooling error.
USAGE
}

die() {
  printf 'edge-probe: %s\n' "$*" >&2
  exit 2
}

cleanup() {
  if [[ -n "${WORKDIR}" && -d "${WORKDIR}" ]]; then
    rm -rf -- "${WORKDIR}"
  fi
}

# --------------------------------------------------------------------------
# Pure parsers. Every function below reads a transcript on stdin and writes one
# classification token to stdout. They are pure so the regression battery can
# feed them real captured transcripts instead of re-probing the internet;
# sourcing this file defines them without running anything.
# --------------------------------------------------------------------------

# Classify an `openssl s_client` transcript.
#
# Prints one of:
#   accepted <version>  handshake completed; <version> is the negotiated
#                       protocol, or "unknown" when the summary line is absent
#                       (LibreSSL). OpenSSL's `New,` line reports TLSv1.0 for a
#                       TLS 1.1 connection, so it is never read as a version.
#   refused             the server rejected the protocol at the TLS layer
#   client-limited      the local client could not attempt it at all
#   error <reason>      transport or unclassified failure -- never a verdict
#
# TWO SIGNALS, IN THIS ORDER, AND NEITHER IS OPTIONAL:
#
#   1. The handshake-completed signal is `^New, TLSv<digit>`. It is NOT the
#      `Protocol:` line. OpenSSL 3.x prints `Protocol: TLSv1` even on a
#      handshake it just failed, alongside `New, (NONE), Cipher is (NONE)` --
#      captured live on 2026-08-12 against a server that refused TLS 1.0. A
#      parser keyed on `Protocol:` alone therefore reports "TLS 1.0 accepted"
#      for a server that correctly refused it: the exact false PASS this probe
#      exists to prevent, and the mirror image of the attestation's §9.2 false
#      FAIL.
#   2. Only once the handshake is known to have completed is the UNINDENTED
#      `Protocol:` summary line read for the version. The indented
#      `    Protocol  :` line inside `SSL-Session:` is never matched: that
#      block is absent for a short TLS 1.3 connection, and the parser keyed on
#      it reported HANDSHAKE-FAILED for a handshake that plainly succeeded
#      (attestation §9.2).
classify_tls_transcript() {
  local transcript summary version
  transcript="$(cat)"
  if printf '%s\n' "${transcript}" \
    | "${GREP}" -q -E -e '[Uu]nknown option' -e 'unknown protocol'; then
    printf 'client-limited\n'
    return 0
  fi
  if printf '%s\n' "${transcript}" | "${GREP}" -q -E -e '^New, TLSv[0-9]'; then
    summary="$(printf '%s\n' "${transcript}" \
      | "${GREP}" -m1 -E -e '^Protocol[[:blank:]]*:' || true)"
    version="${summary#*:}"
    version="${version//[[:blank:]]/}"
    printf 'accepted %s\n' "${version:-unknown}"
    return 0
  fi
  if printf '%s\n' "${transcript}" | "${GREP}" -q -E \
    -e '^New, \(NONE\)' \
    -e 'alert protocol version' \
    -e 'alert handshake failure' \
    -e 'no protocols available' \
    -e 'unsupported protocol' \
    -e 'wrong version number' \
    -e 'sslv3 alert' \
    -e 'tlsv1 alert'; then
    printf 'refused\n'
    return 0
  fi
  if printf '%s\n' "${transcript}" | "${GREP}" -q -E \
    -e 'connect:errno' \
    -e 'Connection refused' \
    -e 'getaddrinfo' \
    -e 'Name or service not known' \
    -e 'no such host'; then
    printf 'error transport\n'
    return 0
  fi
  printf 'error unclassified\n'
}

# Classify a TLS 1.3 transcript for early-data posture.
#
# Prints "off" when every advertised ticket carries Max Early Data: 0, "on"
# when any ticket advertises a nonzero budget, and "no-ticket" when no ticket
# was observed at all. "no-ticket" is never a pass: it is the signature of the
# stdin-close probe defect (`echo |` instead of a real HEAD request with
# -ign_eof), and the caller reports it as SKIP with that explanation.
early_data_verdict() {
  local transcript values value
  transcript="$(cat)"
  values="$(printf '%s\n' "${transcript}" \
    | "${GREP}" -e 'Max Early Data' | tr -dc '0-9\n' || true)"
  if [[ -z "${values//[[:space:]]/}" ]]; then
    printf 'no-ticket\n'
    return 0
  fi
  while IFS= read -r value; do
    [[ -n "${value}" ]] || continue
    if [[ "${value}" != 0 ]]; then
      printf 'on\n'
      return 0
    fi
  done <<<"${values}"
  printf 'off\n'
}

# Classify a Strict-Transport-Security header value against the exact target.
# Prints "exact", "extra <value>" (max-age correct but directives added),
# "wrong <value>", or "absent".
hsts_verdict() {
  local value
  value="$(cat)"
  value="$(printf '%s' "${value}" | tr -d '\r')"
  value="${value#*:}"
  # Collapse surrounding blanks without collapsing the value itself.
  value="${value#"${value%%[![:blank:]]*}"}"
  value="${value%"${value##*[![:blank:]]}"}"
  if [[ -z "${value}" ]]; then
    printf 'absent\n'
    return 0
  fi
  if [[ "${value}" == "${HSTS_TARGET}" ]]; then
    printf 'exact\n'
    return 0
  fi
  if [[ "${value}" == "${HSTS_TARGET}"* ]]; then
    printf 'extra %s\n' "${value}"
    return 0
  fi
  printf 'wrong %s\n' "${value}"
}

# Classify a full `dig` answer for the existence of a name.
#
# Prints "absent-nxdomain", "absent-nodata", "present <count>", or
# "error <status>". NOERROR with ANSWER: 0 is accepted as absence because a
# DNSSEC-signed Cloudflare zone answers every nonexistent name that way
# (compact denial of existence) and never returns NXDOMAIN.
dns_absence_verdict() {
  local answer status count
  answer="$(cat)"
  status="$(printf '%s\n' "${answer}" \
    | "${GREP}" -m1 -o -E -e 'status: [A-Z]+' || true)"
  status="${status#status: }"
  count="$(printf '%s\n' "${answer}" \
    | "${GREP}" -m1 -o -E -e 'ANSWER: [0-9]+' || true)"
  count="${count#ANSWER: }"
  if [[ "${status}" == 'NXDOMAIN' ]]; then
    printf 'absent-nxdomain\n'
    return 0
  fi
  if [[ "${status}" != 'NOERROR' || -z "${count}" ]]; then
    printf 'error %s\n' "${status:-none}"
    return 0
  fi
  if [[ "${count}" == 0 ]]; then
    printf 'absent-nodata\n'
    return 0
  fi
  printf 'present %s\n' "${count}"
}

# Report whether a `dig +dnssec` answer carries the AD (authenticated data)
# flag. Prints "ad" or "no-ad".
dnssec_ad_verdict() {
  local answer flags
  answer="$(cat)"
  flags="$(printf '%s\n' "${answer}" | "${GREP}" -m1 -o -E -e 'flags:[a-z ]*' || true)"
  if [[ " ${flags} " == *' ad '* ]]; then
    printf 'ad\n'
  else
    printf 'no-ad\n'
  fi
}

# --------------------------------------------------------------------------
# Bounded execution. timeout(1) is absent on the operator host, so processes
# are supervised here with nothing but bash builtins and kill(1).
# --------------------------------------------------------------------------
run_bounded() {
  local limit="$1" output="$2"
  shift 2
  local pid waited status
  "$@" >"${output}" 2>&1 &
  pid=$!
  waited=0
  while kill -0 "${pid}" 2>/dev/null; do
    if (( waited >= limit )); then
      kill -TERM "${pid}" 2>/dev/null || true
      sleep 1
      kill -KILL "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
      return 124
    fi
    sleep 1
    waited=$(( waited + 1 ))
  done
  if wait "${pid}"; then
    status=0
  else
    status=$?
  fi
  return "${status}"
}

# --------------------------------------------------------------------------
# Tooling
# --------------------------------------------------------------------------
resolve_openssl() {
  local candidate found
  found=''
  for candidate in \
    "${EDGE_PROBE_OPENSSL:-}" \
    /opt/homebrew/bin/openssl \
    /opt/homebrew/opt/openssl@3/bin/openssl \
    /usr/local/opt/openssl@3/bin/openssl \
    "$(command -v openssl 2>/dev/null || true)" \
    /usr/bin/openssl; do
    [[ -n "${candidate}" && -x "${candidate}" ]] || continue
    if "${candidate}" version 2>/dev/null | "${GREP}" -q -e '^OpenSSL 3'; then
      printf '%s 3\n' "${candidate}"
      return 0
    fi
    [[ -n "${found}" ]] || found="${candidate}"
  done
  [[ -n "${found}" ]] || return 1
  printf '%s other\n' "${found}"
}

require_tools() {
  local resolved
  CURL="$(command -v curl || true)"
  DIG="$(command -v dig || true)"
  [[ -n "${CURL}" ]] || die 'curl is required; this script never installs tools'
  [[ -n "${DIG}" ]] || die 'dig is required; this script never installs tools'
  resolved="$(resolve_openssl || true)"
  [[ -n "${resolved}" ]] || die 'openssl is required; this script never installs tools'
  OPENSSL="${resolved% *}"
  if [[ "${resolved##* }" == 3 ]]; then
    OPENSSL_IS_THREE=yes
  else
    OPENSSL_IS_THREE=no
  fi
}

# --------------------------------------------------------------------------
# Capability preflight (attestation §12 tier 3). A legacy-TLS "failure" is
# meaningless unless the client is proven capable, so each protocol is first
# spoken to a throwaway local s_server on the loopback interface. No packet
# leaves the host, and the throwaway key lives mode 0600 in the per-run
# temporary directory and is removed on exit.
# --------------------------------------------------------------------------
preflight_protocol() {
  local proto="$1"
  local port server_pid client_log server_log verdict
  client_log="${WORKDIR}/preflight-${proto}-client.txt"
  server_log="${WORKDIR}/preflight-${proto}-server.txt"
  verdict=unavailable
  for _ in 1 2 3; do
    port=$(( 20000 + (RANDOM % 20000) ))
    if [[ "${proto}" == tls1_3 ]]; then
      "${OPENSSL}" s_server -www -naccept 1 -accept "127.0.0.1:${port}" \
        -cert "${WORKDIR}/local-cert.pem" -key "${WORKDIR}/local-key.pem" \
        "-${proto}" -cipher 'ALL:@SECLEVEL=0' \
        -ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384 \
        >"${server_log}" 2>&1 &
    else
      "${OPENSSL}" s_server -www -naccept 1 -accept "127.0.0.1:${port}" \
        -cert "${WORKDIR}/local-cert.pem" -key "${WORKDIR}/local-key.pem" \
        "-${proto}" -cipher 'ALL:@SECLEVEL=0' \
        >"${server_log}" 2>&1 &
    fi
    server_pid=$!
    sleep 1
    if ! kill -0 "${server_pid}" 2>/dev/null; then
      wait "${server_pid}" 2>/dev/null || true
      continue
    fi
    run_bounded 10 "${client_log}" \
      "${OPENSSL}" s_client -connect "127.0.0.1:${port}" "-${proto}" \
      -cipher 'ALL:@SECLEVEL=0' </dev/null || true
    kill -TERM "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
    verdict="$(classify_tls_transcript <"${client_log}")"
    [[ "${verdict}" == error* ]] || break
  done
  case "${verdict}" in
    accepted*) printf 'capable\n' ;;
    client-limited) printf 'incapable\n' ;;
    *) printf 'unproven\n' ;;
  esac
}

run_preflight() {
  umask 077
  "${OPENSSL}" req -x509 -newkey rsa:2048 \
    -keyout "${WORKDIR}/local-key.pem" -out "${WORKDIR}/local-cert.pem" \
    -days 1 -nodes -subj '/CN=localhost' >"${WORKDIR}/local-cert.log" 2>&1 \
    || die 'could not create the throwaway loopback certificate for the capability preflight'
  chmod 600 "${WORKDIR}/local-key.pem"
  PREFLIGHT_TLS1="$(preflight_protocol tls1)"
  PREFLIGHT_TLS1_1="$(preflight_protocol tls1_1)"
  PREFLIGHT_TLS1_2="$(preflight_protocol tls1_2)"
  PREFLIGHT_TLS1_3="$(preflight_protocol tls1_3)"
}

preflight_state() {
  case "$1" in
    tls1) printf '%s\n' "${PREFLIGHT_TLS1}" ;;
    tls1_1) printf '%s\n' "${PREFLIGHT_TLS1_1}" ;;
    tls1_2) printf '%s\n' "${PREFLIGHT_TLS1_2}" ;;
    tls1_3) printf '%s\n' "${PREFLIGHT_TLS1_3}" ;;
    *) printf 'unproven\n' ;;
  esac
}

# --------------------------------------------------------------------------
# Records. One tab-separated line per observation; rounds are compared at the
# end so a disagreement is reported instead of silently resolved.
# --------------------------------------------------------------------------
record() {
  local round="$1" zone="$2" item="$3" tier="$4" verdict="$5" observed="$6" note="$7"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${round}" "${zone}" "${item}" "${tier}" "${verdict}" \
    "$(printf '%s' "${observed}" | tr '\t\n' '  ')" \
    "$(printf '%s' "${note}" | tr '\t\n' '  ')" >>"${RECORDS}"
}

# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------
probe_http_redirect() {
  local round="$1" zone="$2" item="$3" path="$4"
  local out code location expected hops
  out="${WORKDIR}/${zone}-${item}-${round}.txt"
  expected="https://${zone}${path}"
  if ! "${CURL}" --silent --show-error --max-time "${TIMEOUT}" \
    --output /dev/null --write-out '%{http_code} %{redirect_url}' \
    "http://${zone}${path}" >"${out}" 2>&1; then
    record "${round}" "${zone}" "${item}" assert ERROR "curl-failed" \
      'the plaintext HTTP request could not complete'
    return 0
  fi
  code="$(cut -d' ' -f1 <"${out}")"
  location="$(cut -d' ' -f2- <"${out}")"
  location="${location# }"
  case "${code}" in
    301|308)
      if [[ "${location}" != "${expected}" ]]; then
        if [[ "${location}" == http://* ]]; then
          record "${round}" "${zone}" "${item}" assert GAP \
            "http_code=${code} location=${location}" \
            "the redirect stays on plaintext http; expected ${expected}"
        else
          record "${round}" "${zone}" "${item}" assert GAP \
            "http_code=${code} location=${location:-<none>}" \
            "the redirect does not preserve path and query; expected ${expected}"
        fi
        return 0
      fi
      hops="$("${CURL}" --silent --show-error --max-time "${TIMEOUT}" \
        --location --max-redirs 5 --output /dev/null \
        --write-out '%{num_redirects}:%{http_code}' "http://${zone}${path}" 2>/dev/null || printf 'error')"
      if [[ "${hops}" != 1:* ]]; then
        record "${round}" "${zone}" "${item}" assert GAP \
          "http_code=${code} location=${location} chain=${hops}" \
          'the target state is exactly one redirect hop'
        return 0
      fi
      record "${round}" "${zone}" "${item}" assert PASS \
        "http_code=${code} location=${location} chain=${hops}" ''
      ;;
    302|303|307)
      record "${round}" "${zone}" "${item}" assert GAP \
        "http_code=${code} location=${location:-<none>}" \
        'the target state is a permanent redirect (301 or 308)'
      ;;
    *)
      record "${round}" "${zone}" "${item}" assert GAP \
        "http_code=${code} location=${location:-<none>}" \
        'plaintext HTTP is served directly; Always Use HTTPS is off'
      ;;
  esac
}

# Record whether Strict-Transport-Security is emitted over PLAINTEXT http.
#
# This is a deployed-state signal, not a security control: RFC 6797 section 7.2
# requires a user agent to ignore an HSTS header received over a non-secure
# transport, so its presence protects nobody and its absence costs nothing.
# What it tells you is WHICH application build is actually serving. The
# https-gated HSTS behaviour is merged in both site repositories but the
# running images predate that merge, so the header is present over cleartext
# today and disappears once the newer images are deployed. Recording it is how
# the runbook's "merged in Git" precondition stops being mistaken for "live at
# the edge".
#
# Once Always Use HTTPS is on, the edge answers the plaintext request itself
# and the origin is never reached, so this item stops carrying information
# about the application build. That is expected, and noted in the output.
probe_cleartext_hsts() {
  local round="$1" zone="$2"
  local out header
  out="${WORKDIR}/${zone}-cleartext-headers-${round}.txt"
  if ! "${CURL}" --silent --show-error --max-time "${TIMEOUT}" \
    --dump-header "${out}" --output /dev/null "http://${zone}/" 2>/dev/null; then
    record "${round}" "${zone}" hsts-over-cleartext record RECORD 'unavailable' \
      'the plaintext request could not complete'
    return 0
  fi
  header="$("${GREP}" -i -m1 -e '^strict-transport-security:' "${out}" || true)"
  if [[ -n "${header}" ]]; then
    record "${round}" "${zone}" hsts-over-cleartext record RECORD 'present' \
      'the origin emits HSTS over cleartext, so the running build predates the https-gated HSTS change; browsers ignore it (RFC 6797 7.2) and it never substitutes for the edge redirect'
  else
    record "${round}" "${zone}" hsts-over-cleartext record RECORD 'absent' \
      'no HSTS over cleartext: either the https-gated build is deployed, or the edge is already answering the plaintext request itself'
  fi
}

probe_tls_version() {
  local round="$1" zone="$2" item="$3" proto="$4" expectation="$5"
  local out capability verdict
  out="${WORKDIR}/${zone}-${item}-${round}.txt"
  capability="$(preflight_state "${proto}")"
  if [[ "${capability}" != capable ]]; then
    record "${round}" "${zone}" "${item}" assert SKIP "client=${capability}" \
      "the local TLS client could not be proven able to speak ${proto} against a local server, so a remote result would describe the client, not the edge"
    return 0
  fi
  run_bounded "${TIMEOUT}" "${out}" \
    "${OPENSSL}" s_client -connect "${zone}:443" -servername "${zone}" \
    "-${proto}" -cipher 'ALL:@SECLEVEL=0' </dev/null || true
  verdict="$(classify_tls_transcript <"${out}")"
  case "${expectation}:${verdict}" in
    refused:refused)
      record "${round}" "${zone}" "${item}" assert PASS "${verdict}" '' ;;
    refused:accepted*)
      record "${round}" "${zone}" "${item}" assert GAP "${verdict}" \
        'the zone minimum TLS version is below 1.2' ;;
    accepted:accepted*)
      record "${round}" "${zone}" "${item}" assert PASS "${verdict}" '' ;;
    accepted:refused)
      record "${round}" "${zone}" "${item}" assert GAP "${verdict}" \
        'a required modern protocol was refused by the edge' ;;
    *)
      record "${round}" "${zone}" "${item}" assert ERROR "${verdict}" \
        'the handshake produced no classifiable result' ;;
  esac
}

probe_zero_rtt() {
  local round="$1" zone="$2"
  local out request verdict
  out="${WORKDIR}/${zone}-zero-rtt-${round}.txt"
  request="${WORKDIR}/${zone}-zero-rtt-${round}.req"
  if [[ "$(preflight_state tls1_3)" != capable ]]; then
    record "${round}" "${zone}" zero-rtt-off assert SKIP 'client=incapable' \
      'the local client could not be proven able to speak TLS 1.3'
    return 0
  fi
  # A real HEAD request with -ign_eof keeps the connection open long enough for
  # the post-handshake session tickets to arrive; `echo |` closes stdin first
  # and produces a false "no ticket" (attestation §9 divergence 1).
  printf 'HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "${zone}" >"${request}"
  run_bounded "${TIMEOUT}" "${out}" \
    "${OPENSSL}" s_client -connect "${zone}:443" -servername "${zone}" \
    -tls1_3 -ign_eof <"${request}" || true
  verdict="$(early_data_verdict <"${out}")"
  case "${verdict}" in
    off) record "${round}" "${zone}" zero-rtt-off assert PASS 'max-early-data=0' '' ;;
    on) record "${round}" "${zone}" zero-rtt-off assert GAP 'max-early-data>0' \
      '0-RTT is enabled at the edge; replayable early data is accepted' ;;
    *) record "${round}" "${zone}" zero-rtt-off assert SKIP 'no-ticket' \
      'no post-handshake session ticket was observed; this is the signature of a truncated probe, not evidence about the edge' ;;
  esac
}

probe_https_headers() {
  local round="$1" zone="$2"
  local out header verdict missing name value
  out="${WORKDIR}/${zone}-headers-${round}.txt"
  if ! "${CURL}" --silent --show-error --max-time "${TIMEOUT}" \
    --dump-header "${out}" --output /dev/null "https://${zone}/" 2>/dev/null; then
    record "${round}" "${zone}" hsts-exact assert ERROR curl-failed 'the HTTPS request could not complete'
    record "${round}" "${zone}" security-headers assert ERROR curl-failed 'the HTTPS request could not complete'
    return 0
  fi
  header="$("${GREP}" -i -m1 -e '^strict-transport-security:' "${out}" || true)"
  verdict="$(printf '%s' "${header}" | hsts_verdict)"
  case "${verdict}" in
    exact) record "${round}" "${zone}" hsts-exact assert PASS "${HSTS_TARGET}" '' ;;
    absent) record "${round}" "${zone}" hsts-exact assert GAP 'absent' \
      'no Strict-Transport-Security header on the HTTPS response' ;;
    *) record "${round}" "${zone}" hsts-exact assert GAP "${verdict}" \
      "the target state is exactly ${HSTS_TARGET}" ;;
  esac
  missing=''
  for name in ${SECURITY_HEADERS}; do
    if ! "${GREP}" -q -i -e "^${name}:" "${out}"; then
      missing="${missing} ${name}"
    fi
  done
  if [[ -n "${missing}" ]]; then
    record "${round}" "${zone}" security-headers assert GAP "missing:${missing# }" \
      'the application response header set is incomplete'
  else
    record "${round}" "${zone}" security-headers assert PASS 'all-present' ''
  fi
  value="$("${GREP}" -i -m1 -e '^alt-svc:' "${out}" | tr -d '\r' || true)"
  record "${round}" "${zone}" alt-svc record RECORD "${value:-<none>}" \
    'HTTP/3 advertisement only; QUIC connectivity is not tested here'
  value="$("${GREP}" -i -m1 -e '^cf-ray:' "${out}" | tr -d '\r' || true)"
  record "${round}" "${zone}" edge-colo record RECORD "${value##*-}" \
    'the colo serving this vantage point; Cloudflare configuration is global'
}

probe_readyz() {
  local round="$1" zone="$2"
  local out code body
  out="${WORKDIR}/${zone}-readyz-${round}.txt"
  if ! "${CURL}" --silent --show-error --max-time "${TIMEOUT}" \
    --write-out '\n%{http_code}' "https://${zone}/readyz" >"${out}" 2>&1; then
    record "${round}" "${zone}" readyz assert ERROR curl-failed 'the readiness request could not complete'
    return 0
  fi
  code="$(tail -n1 <"${out}")"
  body="$(head -n1 <"${out}")"
  if [[ "${code}" == 200 ]]; then
    record "${round}" "${zone}" readyz assert PASS "http_code=200 body=${body}" ''
  else
    record "${round}" "${zone}" readyz assert GAP "http_code=${code}" \
      'the public readiness endpoint is not answering 200'
  fi
}

probe_identity() {
  local round="$1" zone="$2" other="$3"
  local out title assets bytes
  out="${WORKDIR}/${zone}-body-${round}.html"
  if ! "${CURL}" --silent --show-error --max-time "${TIMEOUT}" \
    --output "${out}" "https://${zone}/" 2>/dev/null; then
    record "${round}" "${zone}" site-identity assert ERROR curl-failed 'the root request could not complete'
    return 0
  fi
  title="$("${GREP}" -o -m1 -E -e '<title>[^<]*</title>' "${out}" || true)"
  title="${title#<title>}"
  title="${title%</title>}"
  # Assets are the distinctness marker together with the title. The whole-body
  # hash is deliberately never used: Cloudflare injects a per-request ray ID
  # into every HTML response, so it differs between two identical rounds. The
  # <h1> is deliberately never used either: it is identical on both sites.
  assets="$("${GREP}" -o -E -e '/assets/index-[A-Za-z0-9_-]+\.(js|css)' "${out}" \
    | sort -u | tr '\n' ',' || true)"
  bytes="$(wc -c <"${out}" | tr -d ' ')"
  if [[ "${title}" != "${zone}" ]]; then
    record "${round}" "${zone}" site-identity assert GAP "title=${title:-<none>}" \
      'the apex does not serve its own identity'
  elif [[ -n "${other}" ]] && "${GREP}" -q -F -e "<title>${other}</title>" "${out}"; then
    record "${round}" "${zone}" site-identity assert GAP "title=${title}" \
      'the response also carries the other site identity'
  else
    record "${round}" "${zone}" site-identity assert PASS "title=${title}" ''
  fi
  record "${round}" "${zone}" assets record RECORD "${assets%,}" \
    'asset filenames are the distinctness marker; the body hash never is'
  record "${round}" "${zone}" body-bytes record RECORD "${bytes}" \
    'body length is stable across rounds; the body hash is not'
}

probe_certificate() {
  local round="$1" zone="$2"
  local raw chain out notafter seconds
  raw="${WORKDIR}/${zone}-handshake-${round}.txt"
  chain="${WORKDIR}/${zone}-leaf-${round}.pem"
  out="${WORKDIR}/${zone}-cert-${round}.txt"
  if ! run_bounded "${TIMEOUT}" "${raw}" \
    "${OPENSSL}" s_client -connect "${zone}:443" -servername "${zone}" </dev/null; then
    record "${round}" "${zone}" cert-headroom assert ERROR handshake-failed 'the certificate could not be read'
    return 0
  fi
  # s_client merges progress output onto the same stream; take exactly the
  # first PEM block so no diagnostic line can reach the parser.
  awk '/-----BEGIN CERTIFICATE-----/ { inside = 1 }
       inside { print }
       /-----END CERTIFICATE-----/ { if (inside) exit }' "${raw}" >"${chain}"
  seconds=$(( CERT_MIN_DAYS * 86400 ))
  # -checkend is used instead of date arithmetic on purpose: it needs no GNU
  # date and behaves identically on macOS and Linux.
  if "${OPENSSL}" x509 -noout -checkend "${seconds}" <"${chain}" >"${out}" 2>&1; then
    record "${round}" "${zone}" cert-headroom assert PASS "more-than-${CERT_MIN_DAYS}-days" ''
  else
    record "${round}" "${zone}" cert-headroom assert GAP "less-than-${CERT_MIN_DAYS}-days" \
      'the leaf certificate is inside the renewal alert threshold'
  fi
  notafter="$("${OPENSSL}" x509 -noout -enddate <"${chain}" 2>/dev/null || true)"
  record "${round}" "${zone}" cert-notafter record RECORD "${notafter#notAfter=}" \
    'recorded for the audit trail; certificate identity is never gated on'
}

probe_tls_details() {
  local round="$1" zone="$2"
  local out group alpn
  out="${WORKDIR}/${zone}-tls13-details-${round}.txt"
  if [[ "$(preflight_state tls1_3)" != capable ]]; then
    return 0
  fi
  run_bounded "${TIMEOUT}" "${out}" \
    "${OPENSSL}" s_client -connect "${zone}:443" -servername "${zone}" \
    -tls1_3 -alpn h2,http/1.1 </dev/null || true
  group="$("${GREP}" -m1 -e 'Negotiated TLS1.3 group' "${out}" || true)"
  alpn="$("${GREP}" -m1 -e 'ALPN protocol' "${out}" || true)"
  record "${round}" "${zone}" tls13-group record RECORD "${group#*: }" \
    'Cloudflare rotates negotiated defaults; recorded, never gated'
  record "${round}" "${zone}" alpn record RECORD "${alpn#*: }" \
    'recorded, never gated'
}

probe_dnssec() {
  local round="$1" zone="$2" expectation="$3"
  local ds_one ds_two ad_one ad_two ad_cd observed
  ds_one="$("${DIG}" "@${RESOLVER_ONE}" DS "${zone}" +short 2>/dev/null || true)"
  ds_two="$("${DIG}" "@${RESOLVER_TWO}" DS "${zone}" +short 2>/dev/null || true)"
  ad_one="$("${DIG}" "@${RESOLVER_ONE}" A "${zone}" +dnssec 2>/dev/null | dnssec_ad_verdict)"
  ad_two="$("${DIG}" "@${RESOLVER_TWO}" A "${zone}" +dnssec 2>/dev/null | dnssec_ad_verdict)"
  # Negative control: with checking disabled the AD flag must disappear, which
  # proves the AD flag above is a real validation result and not an artifact.
  ad_cd="$("${DIG}" "@${RESOLVER_ONE}" A "${zone}" +cd +dnssec 2>/dev/null | dnssec_ad_verdict)"
  observed="ds1=$([[ -n "${ds_one}" ]] && printf present || printf absent)"
  observed="${observed} ds2=$([[ -n "${ds_two}" ]] && printf present || printf absent)"
  observed="${observed} ${ad_one}/${ad_two} cd=${ad_cd}"
  if [[ "${expectation}" == signed ]]; then
    if [[ -n "${ds_one}" && -n "${ds_two}" && "${ad_one}" == ad && "${ad_two}" == ad && "${ad_cd}" == no-ad ]]; then
      record "${round}" "${zone}" dnssec assert PASS "${observed}" ''
    else
      record "${round}" "${zone}" dnssec assert GAP "${observed}" \
        'the zone is expected to be signed and validating at two independent resolvers with the negative control clearing AD'
    fi
  else
    if [[ -z "${ds_one}" && -z "${ds_two}" && "${ad_one}" == no-ad && "${ad_two}" == no-ad ]]; then
      record "${round}" "${zone}" dnssec assert PASS "${observed}" \
        'unsigned is the recorded expectation for this zone until the owner signing ceremony'
      record "${round}" "${zone}" dnssec-parity record RECORD 'unsigned' \
        'signing parity with the other zone is pending an owner ceremony; not a defect of this run'
    else
      record "${round}" "${zone}" dnssec assert GAP "${observed}" \
        'the zone state changed from the recorded unsigned expectation; re-read the expectation before trusting this verdict'
    fi
  fi
}

probe_www_absent() {
  local round="$1" zone="$2" expectation="$3"
  local one two note
  one="$("${DIG}" "@${RESOLVER_ONE}" A "www.${zone}" 2>/dev/null | dns_absence_verdict)"
  two="$("${DIG}" "@${RESOLVER_TWO}" A "www.${zone}" 2>/dev/null | dns_absence_verdict)"
  note=''
  if [[ "${expectation}" == signed ]]; then
    note='NOERROR/NODATA rather than NXDOMAIN is the expected shape on a DNSSEC-signed Cloudflare zone (compact denial of existence)'
  fi
  if [[ "${one}" == absent-* && "${two}" == absent-* ]]; then
    record "${round}" "${zone}" www-absent assert PASS "${one} ${two}" "${note}"
  elif [[ "${one}" == error* || "${two}" == error* ]]; then
    record "${round}" "${zone}" www-absent assert ERROR "${one} ${two}" 'the resolvers did not answer'
  else
    record "${round}" "${zone}" www-absent assert GAP "${one} ${two}" \
      'a www record exists; ADR 0015 leaves www as terminal 404 or one exact redirect, never a new address record'
  fi
}

probe_zone() {
  local round="$1" zone="$2" other="$3" dnssec_expectation="$4"
  probe_http_redirect "${round}" "${zone}" http-redirect-root '/'
  probe_http_redirect "${round}" "${zone}" http-redirect-path-query '/readyz?probe=1&x=2'
  probe_cleartext_hsts "${round}" "${zone}"
  probe_tls_version "${round}" "${zone}" tls10-refused tls1 refused
  probe_tls_version "${round}" "${zone}" tls11-refused tls1_1 refused
  probe_tls_version "${round}" "${zone}" tls12-accepted tls1_2 accepted
  probe_tls_version "${round}" "${zone}" tls13-accepted tls1_3 accepted
  probe_zero_rtt "${round}" "${zone}"
  probe_https_headers "${round}" "${zone}"
  probe_readyz "${round}" "${zone}"
  probe_identity "${round}" "${zone}" "${other}"
  probe_certificate "${round}" "${zone}"
  probe_tls_details "${round}" "${zone}"
  probe_dnssec "${round}" "${zone}" "${dnssec_expectation}"
  probe_www_absent "${round}" "${zone}" "${dnssec_expectation}"
}

probe_cross_zone_distinctness() {
  local round="$1"
  local a b
  if [[ "${ZONES}" != "${ZONE_A} ${ZONE_B}" ]]; then
    # INAPPLICABLE, not SKIP, and the distinction is load-bearing. A SKIP means
    # "this target could not be proven", which --enforce must treat as unmet. A
    # single-zone run has no second site to compare against, so the item does
    # not apply to the selected scope at all -- there is nothing unproven about
    # it. Recording it as an asserted SKIP made every single-zone --enforce run
    # exit 1 no matter how healthy the zone was, which trains an operator to
    # wave a nonzero exit through in the middle of a half-completed toggle
    # ceremony. Inapplicable is not the same as unproven.
    record "${round}" both sites-distinct record INAPPLICABLE 'single-zone-run' \
      'cross-zone distinctness needs both sites in the same run; this item does not apply to the selected scope and is not an unproven target'
    return 0
  fi
  a="$(awk -F'\t' -v r="${round}" -v z="${ZONE_A}" '$1==r && $2==z && $3=="assets" {print $6}' "${RECORDS}")"
  b="$(awk -F'\t' -v r="${round}" -v z="${ZONE_B}" '$1==r && $2==z && $3=="assets" {print $6}' "${RECORDS}")"
  if [[ -z "${a}" || -z "${b}" ]]; then
    record "${round}" both sites-distinct assert ERROR 'assets-unavailable' \
      'asset filenames could not be read from one of the sites'
  elif [[ "${a}" == "${b}" ]]; then
    record "${round}" both sites-distinct assert GAP 'assets-identical' \
      'both sites served the same asset filenames'
  else
    record "${round}" both sites-distinct assert PASS 'assets-disjoint' ''
  fi
}

# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
# Collapse the per-round records into one verdict per zone/item. Rounds that
# disagree collapse to DIVERGENT rather than to the last value seen: a probe
# that answers differently twice has told us something, and hiding it would
# reproduce exactly the class of defect this script exists to avoid.
final_verdicts() {
  awk -F'\t' '
    {
      key = $2 "\t" $3
      if (!(key in tier)) { order[++n] = key; tier[key] = $4; verdict[key] = $5 }
      else if (verdict[key] != $5) { verdict[key] = "DIVERGENT" }
      observed[key] = $6
      if ($7 != "") { note[key] = $7 }
    }
    END {
      for (i = 1; i <= n; i++) {
        key = order[i]
        printf "%s\t%s\t%s\t%s\t%s\n", key, tier[key], verdict[key], observed[key], note[key]
      }
    }
  ' "${RECORDS}"
}

print_report() {
  local verdicts pass gap skip error divergent record_count exit_code
  local inapplicable
  verdicts="${WORKDIR}/verdicts.tsv"
  final_verdicts >"${verdicts}"

  printf '\n## capability preflight (local loopback only)\n'
  printf '%-10s %s\n' 'tls1' "${PREFLIGHT_TLS1}"
  printf '%-10s %s\n' 'tls1_1' "${PREFLIGHT_TLS1_1}"
  printf '%-10s %s\n' 'tls1_2' "${PREFLIGHT_TLS1_2}"
  printf '%-10s %s\n' 'tls1_3' "${PREFLIGHT_TLS1_3}"
  printf 'A protocol the local client cannot speak is reported SKIP, never PASS or GAP.\n'

  printf '\n## records (machine-readable)\n'
  awk -F'\t' -v schema="${SCHEMA}" '{
    printf "ITEM schema=%s zone=%s id=%s tier=%s verdict=%s observed=\"%s\"\n", schema, $1, $2, $3, $4, $5
  }' "${verdicts}"

  printf '\n## table\n'
  printf '%-16s %-26s %-10s %s\n' ZONE ITEM VERDICT OBSERVED
  awk -F'\t' '{ printf "%-16s %-26s %-10s %s\n", $1, $2, $4, $5 }' "${verdicts}"

  printf '\n## notes\n'
  awk -F'\t' '$6 != "" { printf "%s %s: %s\n", $1, $2, $6 }' "${verdicts}"
  printf 'Configuration truth is not observable here: every verdict describes behaviour, never which setting produced it.\n'

  pass="$(awk -F'\t' '$3=="assert" && $4=="PASS"' "${verdicts}" | wc -l | tr -d ' ')"
  gap="$(awk -F'\t' '$3=="assert" && $4=="GAP"' "${verdicts}" | wc -l | tr -d ' ')"
  skip="$(awk -F'\t' '$3=="assert" && $4=="SKIP"' "${verdicts}" | wc -l | tr -d ' ')"
  error="$(awk -F'\t' '$3=="assert" && $4=="ERROR"' "${verdicts}" | wc -l | tr -d ' ')"
  divergent="$(awk -F'\t' '$4=="DIVERGENT"' "${verdicts}" | wc -l | tr -d ' ')"
  record_count="$(awk -F'\t' '$3=="record" && $4=="RECORD"' "${verdicts}" | wc -l | tr -d ' ')"
  inapplicable="$(awk -F'\t' '$4=="INAPPLICABLE"' "${verdicts}" | wc -l | tr -d ' ')"

  # --enforce fails on an unmet target (GAP), an unproven one (SKIP), a probe
  # that could not complete (ERROR), and a probe that answered differently
  # twice (DIVERGENT). It deliberately does NOT fail on INAPPLICABLE: an item
  # outside the selected scope has nothing to prove, and conflating the two
  # made every single-zone enforcing run exit nonzero regardless of the zone's
  # health.
  exit_code=0
  if [[ "${ENFORCE}" == yes ]] \
    && (( gap + skip + error + divergent > 0 )); then
    exit_code=1
  fi
  printf '\nRESULT schema=%s utc=%s zones="%s" rounds=%s pass=%s gap=%s skip=%s error=%s divergent=%s inapplicable=%s recorded=%s enforce=%s exit=%s\n' \
    "${SCHEMA}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${ZONES}" "${ROUNDS}" \
    "${pass}" "${gap}" "${skip}" "${error}" "${divergent}" "${inapplicable}" \
    "${record_count}" "${ENFORCE}" "${exit_code}"
  return "${exit_code}"
}

self_test() {
  local failures status
  failures=0
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/edge-probe-selftest.XXXXXX")"
  trap cleanup EXIT
  require_tools
  printf 'edge-probe self-test (offline; no remote host is contacted)\n'
  printf 'openssl=%s openssl3=%s grep=%s\n' "${OPENSSL}" "${OPENSSL_IS_THREE}" "${GREP}"
  run_preflight
  printf '\ncapability matrix\n'
  printf '%-10s %s\n' tls1 "${PREFLIGHT_TLS1}"
  printf '%-10s %s\n' tls1_1 "${PREFLIGHT_TLS1_1}"
  printf '%-10s %s\n' tls1_2 "${PREFLIGHT_TLS1_2}"
  printf '%-10s %s\n' tls1_3 "${PREFLIGHT_TLS1_3}"

  printf '\nparser checks\n'
  # A real TLS 1.3 s_client summary carries no SSL-Session block; the parser
  # must still report success. This is the exact false negative from §9.2.
  status="$(printf 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nProtocol: TLSv1.3\nVerify return code: 0 (ok)\n' | classify_tls_transcript)"
  printf 'tls13-without-session-block -> %s\n' "${status}"
  [[ "${status}" == 'accepted TLSv1.3' ]] || failures=$(( failures + 1 ))
  status="$(printf 'CONNECTED(00000006)\n40E7...:error:0A0000102:SSL routines:ssl_choose_client_version:unsupported protocol\n' | classify_tls_transcript)"
  printf 'refused-handshake            -> %s\n' "${status}"
  [[ "${status}" == 'refused' ]] || failures=$(( failures + 1 ))
  # OpenSSL prints a Protocol: line even for a handshake it just failed. A
  # parser keyed on that line alone would report the refusal as an acceptance.
  status="$(printf 'error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version\nNew, (NONE), Cipher is (NONE)\nProtocol: TLSv1\n' | classify_tls_transcript)"
  printf 'refused-but-prints-protocol  -> %s\n' "${status}"
  [[ "${status}" == 'refused' ]] || failures=$(( failures + 1 ))
  status="$(printf 'Post-Handshake New Session Ticket arrived:\n    Max Early Data: 0\n' | early_data_verdict)"
  printf 'early-data-zero              -> %s\n' "${status}"
  [[ "${status}" == 'off' ]] || failures=$(( failures + 1 ))
  status="$(printf 'strict-transport-security: max-age=31536000\n' | hsts_verdict)"
  printf 'hsts-exact                   -> %s\n' "${status}"
  [[ "${status}" == 'exact' ]] || failures=$(( failures + 1 ))
  status="$(printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 4\n' | dns_absence_verdict)"
  printf 'nodata-is-absence            -> %s\n' "${status}"
  [[ "${status}" == 'absent-nodata' ]] || failures=$(( failures + 1 ))

  if (( failures > 0 )); then
    printf '\nRESULT schema=%s mode=self-test failures=%s exit=1\n' "${SCHEMA}" "${failures}"
    return 1
  fi
  printf '\nRESULT schema=%s mode=self-test failures=0 exit=0\n' "${SCHEMA}"
  return 0
}

run_probe() {
  local round zone other expectation
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/edge-probe.XXXXXX")"
  trap cleanup EXIT
  RECORDS="${WORKDIR}/records.tsv"
  : >"${RECORDS}"
  require_tools

  printf '## context\n'
  printf 'schema=%s\n' "${SCHEMA}"
  printf 'started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'zones="%s" rounds=%s round_gap=%ss timeout=%ss enforce=%s\n' \
    "${ZONES}" "${ROUNDS}" "${ROUND_GAP}" "${TIMEOUT}" "${ENFORCE}"
  printf 'openssl=%s (%s) curl=%s dig=%s grep=%s\n' \
    "${OPENSSL}" "$("${OPENSSL}" version 2>/dev/null || printf unknown)" \
    "${CURL}" "${DIG}" "${GREP}"
  printf 'resolvers=%s,%s\n' "${RESOLVER_ONE}" "${RESOLVER_TWO}"
  printf 'This run reads only the site hostnames above and those two resolvers. No credential is read or sent.\n'

  run_preflight

  for (( round = 1; round <= ROUNDS; round++ )); do
    if (( round > 1 )); then
      sleep "${ROUND_GAP}"
    fi
    for zone in ${ZONES}; do
      if [[ "${zone}" == "${ZONE_A}" ]]; then
        expectation="${ZONE_A_DNSSEC}"
        other="${ZONE_B}"
      else
        expectation="${ZONE_B_DNSSEC}"
        other="${ZONE_A}"
      fi
      [[ "${ZONES}" == "${ZONE_A} ${ZONE_B}" ]] || other=''
      probe_zone "${round}" "${zone}" "${other}" "${expectation}"
    done
    probe_cross_zone_distinctness "${round}"
  done

  print_report
}

main() {
  local mode status
  mode=probe
  status=0
  ZONES="${ZONE_A} ${ZONE_B}"
  while (( $# > 0 )); do
    case "$1" in
      --enforce) ENFORCE=yes ;;
      --self-test) mode=self-test ;;
      --zone)
        shift || die '--zone needs a hostname'
        case "${1:-}" in
          "${ZONE_A}") ZONES="${ZONE_A}" ;;
          "${ZONE_B}") ZONES="${ZONE_B}" ;;
          *) die "--zone accepts only ${ZONE_A} or ${ZONE_B}" ;;
        esac
        ;;
      --rounds)
        shift || die '--rounds needs a value'
        [[ "${1:-}" =~ ^[1-5]$ ]] || die '--rounds must be 1-5'
        ROUNDS="$1"
        ;;
      --round-gap)
        shift || die '--round-gap needs a value'
        if [[ ! "${1:-}" =~ ^[0-9]{1,3}$ ]] || (( $1 > 600 )); then
          die '--round-gap must be 0-600 seconds'
        fi
        ROUND_GAP="$1"
        ;;
      --timeout)
        shift || die '--timeout needs a value'
        if [[ ! "${1:-}" =~ ^[0-9]{1,3}$ ]] || (( $1 < 5 || $1 > 120 )); then
          die '--timeout must be 5-120 seconds'
        fi
        TIMEOUT="$1"
        ;;
      -h|--help) usage; return 0 ;;
      *) usage >&2; die "unknown argument: $1" ;;
    esac
    shift
  done
  if [[ "${mode}" == self-test ]]; then
    self_test || status=$?
    return "${status}"
  fi
  run_probe
}

# Executed as a command, this runs main. Sourced, it only defines the parsers
# above, which is how the regression battery feeds them captured transcripts.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
