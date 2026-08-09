# Small build-time assets only

This tree is for small, version-controlled UI material that belongs in the
Svelte build: `images/` for lightweight interface artwork, `audio/` and
`video/` for tiny component-local cues only, `icons/` for interface symbols,
`fonts/` for reviewed webfonts and licenses, and `textures/` for compact visual
surfaces. Large photographs, FLAC files, source video, and delivery derivatives
never belong here because Vite would copy them into the frontend, Go would embed
them, and the OCI image would inherit their size and lifecycle. Those assets use
the logical `/media/...` contract from `src/lib/media.ts` and remain on the
separately managed, read-only data volume described by ADR 0012.
