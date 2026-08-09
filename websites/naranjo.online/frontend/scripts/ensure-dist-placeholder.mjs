import { writeFile } from 'node:fs/promises';

const content = `# Replaced by the Svelte build. Keeping the directory lets Go tooling resolve
# the embed pattern before package-lock generation; the server still refuses to
# start/build successfully without a real index.html.
`;

await writeFile('../internal/web/dist/.gitkeep', content, { encoding: 'utf8' });
