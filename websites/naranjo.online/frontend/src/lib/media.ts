// MediaPublication keeps cache behavior explicit at the call site without
// exposing any Pi filesystem, volume, or origin detail to Svelte components.
export type MediaPublication =
  | { kind: 'immutable'; sha256: string; path: string }
  | { kind: 'mutable'; path: string };

// safeDigest keeps immutable URLs in the same canonical form as promotion and
// origin validation, avoiding cache aliases for one content identity.
const safeDigest = /^[0-9a-f]{64}$/;
// safeSegment intentionally narrows operator filenames to URL-stable ASCII;
// dots may occur inside names but hidden, empty, and traversal segments cannot.
const safeSegment = /^[A-Za-z0-9][A-Za-z0-9._~-]*$/;
// reservedSegments mirrors the Go origin's operator-only namespaces. Keeping
// the list here prevents a component from producing a URL the server must hide.
const reservedSegments = new Set([
  'checksums',
  'internal',
  'lost+found',
  'manifests',
  'metadata',
  'originals',
  'staging'
]);

// mediaUrl converts a reviewed logical media identity into the only public URL
// shape the Go origin accepts. Physical storage remains an operator concern,
// and rejecting ambiguous segments prevents components from creating traversal
// or hidden-file URLs that could diverge across browsers and the origin.
export function mediaUrl(publication: MediaPublication): string {
  const segments = publication.path.split('/');
  if (
    publication.path.length === 0 ||
    publication.path.includes('\\') ||
    segments.some(
      (segment) =>
        !safeSegment.test(segment) || reservedSegments.has(segment.toLowerCase())
    )
  ) {
    throw new Error('media path must contain only canonical public segments');
  }

  const encodedPath = segments.map((segment) => encodeURIComponent(segment)).join('/');
  if (publication.kind === 'immutable') {
    if (!safeDigest.test(publication.sha256)) {
      throw new Error('immutable media requires a lowercase SHA-256 digest');
    }
    return `/media/immutable/${publication.sha256}/${encodedPath}`;
  }
  return `/media/mutable/${encodedPath}`;
}
