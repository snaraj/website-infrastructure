import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const [fallback, component, styles] = await Promise.all([
  readFile(new URL('../index.html', import.meta.url), 'utf8'),
  readFile(new URL('../src/App.svelte', import.meta.url), 'utf8'),
  readFile(new URL('../src/styles.css', import.meta.url), 'utf8'),
]);

// Browser execution is deliberately outside this dependency-free test. These
// assertions keep the accessible, responsive first response intact even when
// JavaScript is slow, unavailable, or rejected by a visitor's policy.
test('static and hydrated shells preserve the same accessible identity', () => {
  for (const source of [fallback, component]) {
    assert.match(source, /Hello World!/);
    assert.match(source, /Website coming soon!/);
  }
  assert.match(fallback, /<html lang="en">/);
  assert.match(fallback, /name="viewport"/);
  assert.match(fallback, /data-static-fallback/);
  assert.match(fallback, /<main aria-labelledby="static-page-title"/);
  assert.match(component, /<svelte:head>/);
  assert.match(component, /name="description"/);
  assert.match(component, /<main aria-labelledby="page-title">/);
  assert.match(component, /<h1 id="page-title">Hello World!<\/h1>/);
});

test('initial source remains local and viewport-responsive', () => {
  for (const [name, source] of Object.entries({ fallback, component, styles })) {
    assert.doesNotMatch(source, /(?:https?:)?\/\//, `${name} introduces a remote origin`);
  }
  assert.match(styles, /font-size:\s*clamp\(/);
  assert.match(styles, /min-height:\s*100vh/);
  assert.match(styles, /prefers-color-scheme:\s*light/);
});
