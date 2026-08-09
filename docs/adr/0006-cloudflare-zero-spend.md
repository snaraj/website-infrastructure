# ADR 0006: Cloudflare zero infrastructure spend

- Status: Accepted
- Date: 2026-08-08

## Decision

Cloudflare infrastructure must cost $0. The account boundary is exactly two
active domain zones, each on the Free website plan. Registrar renewals for those
two domains are the only authorized Cloudflare charges and remain classified
separately from infrastructure. The allowlist contains those existing Free
zones, authoritative/proxied DNS, Universal SSL, DNSSEC, Cloudflare Tunnel, and
Zero Trust features whose Free entitlement is verified immediately before use.

Pro is the next paid website plan and is not authorized. The observed 2026-08-08
list price is $20 per domain/month with annual commitment or $25 month-to-month,
so two Pro zones would illustrate $40 or $50 monthly before tax. These figures
document the denied boundary; they never grant approval and must be refreshed
from Cloudflare before any future decision.

Workers, Pages Functions, storage, databases, queues, AI, media, Argo, Spectrum,
Load Balancing, Cache Reserve, paid/usage-based rate limiting, paid certificates,
paid security, trials, upgrades, subscriptions, and unknown products are denied.

Current official documentation reviewed on 2026-08-08 adds a contractual
boundary for `naranjo.online`'s proposed heavy-media use: the self-serve
Application Services terms require Free, Pro, and Business customers to use a
qualifying paid service for video and other large-file patterns. No safe file,
traffic, or bandwidth threshold is published. The documented 512 MB maximum
cacheable file size for Free/Pro/Business is only a technical cache limit;
larger responses bypass cache, and neither BYPASS nor `no-store` bypasses the
service terms or the proxied Tunnel path. Therefore deliberate large-media
delivery remains disabled and is a zero-spend `NO-GO`. Ordinary site pages and
modest UI assets remain subject to the existing audit and launch gates.

## Enforcement

OpenTofu resource allowlisting, plan policy, read-only subscription audits,
least-privilege tokens without Billing Write or Registrar Write, and explicit
plan-hash approval are primary controls. The separate audit token may have
Billing Read. Budget alerts are delayed secondary detection and never authorize
or stop spend. Failure means downtime, never paid fallback.

Official evidence:

- <https://www.cloudflare.com/service-specific-terms-application-services/>
- <https://developers.cloudflare.com/fundamentals/reference/policies-compliances/delivering-videos-with-cloudflare/>
- <https://developers.cloudflare.com/cache/concepts/default-cache-behavior/>
- <https://developers.cloudflare.com/tunnel/routing/>
