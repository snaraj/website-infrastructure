import { writeFile } from 'node:fs/promises';

// Vite empties its output directory on every build. Restoring this non-public
// marker keeps Go's embed pattern valid in source checkouts after generated
// assets are cleaned, without providing a fake production index page.
const content = `# Replaced by the Svelte build. Keeping the directory lets Go tooling resolve
# the embed pattern before the browser bundle is generated; the server still
# refuses to start successfully without a real index.html.
`;

await writeFile('../internal/web/dist/.gitkeep', content, { encoding: 'utf8' });
