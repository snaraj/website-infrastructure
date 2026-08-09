# Website image promotion and rollback — Draft / unverified

Promotion consumes the multi-architecture digest emitted by the selected site's
protected-main CI. Run `scripts/promote-image.sh <naranjo-online|lidersea-com>
sha256:<digest>`; the closed site mapping verifies the exact keyless workflow
identity and provenance, updates only that site's chart digest on a non-main
clean branch, runs available checks, and stops before commit/push.

For rollback, select a retained digest whose signature, provenance, SBOM, scan,
amd64/arm64 manifests, and prior runtime health remain accepted. Run the same
promotion verification, open a reviewed PR changing only the digest, and observe
the rolling update. Never substitute a tag, direct-main push, `kubectl set image`,
or unsigned emergency build. If the prior image is now vulnerable/compromised,
roll forward to a repaired digest instead.
