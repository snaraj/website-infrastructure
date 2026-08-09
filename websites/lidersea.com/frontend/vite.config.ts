import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';

// The build writes directly into the Go embed package so the published image
// contains one immutable artifact rather than separately deployed web assets.
export default defineConfig({
  plugins: [svelte()],
  build: {
    emptyOutDir: true,
    outDir: '../internal/web/dist',
    sourcemap: false,
  },
});
