import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { mediaUrl } from '../src/lib/media.ts';

const digest = 'a'.repeat(64);

describe('mediaUrl', () => {
  it('creates only the two canonical public URL shapes', () => {
    assert.equal(
      mediaUrl({ kind: 'immutable', sha256: digest, path: 'gallery/photo-one.webp' }),
      `/media/immutable/${digest}/gallery/photo-one.webp`
    );
    assert.equal(
      mediaUrl({ kind: 'mutable', path: 'albums/current.flac' }),
      '/media/mutable/albums/current.flac'
    );
  });

  it('rejects paths hidden by the Go origin', () => {
    for (const path of [
      '',
      '../original.flac',
      '.hidden/file.mp4',
      '_private/file.mp4',
      'album\\file.mp4',
      'metadata/file.json',
      'album/ORIGINALS/file.flac'
    ]) {
      assert.throws(() => mediaUrl({ kind: 'mutable', path }), /canonical public segments/);
    }
  });

  it('requires one lowercase SHA-256 digest for immutable publication', () => {
    for (const sha256 of ['a'.repeat(63), 'A'.repeat(64), 'not-a-digest']) {
      assert.throws(
        () => mediaUrl({ kind: 'immutable', sha256, path: 'gallery/photo.webp' }),
        /lowercase SHA-256 digest/
      );
    }
  });
});
