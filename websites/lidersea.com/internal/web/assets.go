// Package web owns the compiled browser application that is shipped inside the
// Go server. Embedding the frontend gives the cluster one immutable artifact to
// promote, sign, scan, and roll back instead of coordinating a separate web
// server and asset deployment.
package web

import (
	"embed"
	"fmt"
	"io/fs"
)

// frontendAssets is populated by the pinned Svelte build before Go compilation.
// Keeping the embed pattern rooted at dist prevents source files and development
// configuration from becoming reachable through the production HTTP server.
//
//go:embed dist/*
var frontendAssets embed.FS

// FileSystem returns a read-only view rooted at the generated frontend output.
// The server receives fs.FS rather than embed.FS so its HTTP behavior can be
// tested against an in-memory filesystem without rebuilding the Svelte bundle.
func FileSystem() (fs.FS, error) {
	assets, err := fs.Sub(frontendAssets, "dist")
	if err != nil {
		return nil, fmt.Errorf("open embedded frontend: %w", err)
	}
	return assets, nil
}
