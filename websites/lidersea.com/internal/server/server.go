// Package server exposes the production HTTP handler for lidersea.com. It
// serves only the embedded frontend and Kubernetes health probes, keeping the
// application stateless and suitable for replicated, pull-based deployments.
package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// handler serves the immutable frontend files after New has validated the
// bundle's entrypoint. It remains private so callers cannot bypass the mux's
// health endpoints or the securityHeaders wrapper.
type handler struct {
	// assets is the read-only, build-generated frontend filesystem.
	assets fs.FS
	// index is loaded during construction so a broken image fails before the
	// process becomes ready rather than failing on the first visitor request.
	index []byte
}

// New constructs the complete lidersea.com HTTP handler from built frontend
// assets. Construction validates index.html up front, wires Kubernetes probe
// endpoints, and applies one security-header policy to every response.
func New(assets fs.FS) (http.Handler, error) {
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return nil, fmt.Errorf("read embedded index: %w", err)
	}
	h := &handler{assets: assets, index: index}
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", health)
	mux.HandleFunc("/readyz", health)
	mux.Handle("/", h)
	return securityHeaders(mux), nil
}

// health provides the shared liveness and readiness response. The service has
// no database or other runtime dependency, so both probes intentionally use the
// same cheap, side-effect-free check.
func health(w http.ResponseWriter, r *http.Request) {
	if !allowReadMethod(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte("ok\n"))
	}
}

// ServeHTTP maps a clean URL path to a built frontend file. Unknown paths return
// 404 instead of falling back to index.html because this site has no client-side
// router and silently rewriting mistakes would hide broken asset references.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !allowReadMethod(w, r) {
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		// index.html points at content-addressed assets and must be revalidated on
		// every navigation so a rollout is visible without a stale shell page.
		serveBytes(w, r, "index.html", h.index, "no-store")
		return
	}
	if !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	// dist/.gitkeep exists only so a clean checkout can compile before the
	// frontend build. It is build metadata, not public site content.
	if name == ".gitkeep" {
		http.NotFound(w, r)
		return
	}
	info, err := fs.Stat(h.assets, name)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(h.assets, name)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	cacheControl := "no-cache"
	if strings.HasPrefix(name, "assets/") {
		// Vite filenames contain a content hash, making a year-long immutable
		// cache safe: changed bytes are always published under a new URL.
		cacheControl = "public, max-age=31536000, immutable"
	}
	serveBytes(w, r, name, data, cacheControl)
}

// allowReadMethod enforces the read-only contract shared by site and probe
// routes. Rejecting mutation methods closes an unnecessary attack surface.
func allowReadMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// serveBytes applies cache metadata and delegates byte-range, conditional, and
// HEAD behavior to net/http. Its digest-based strong ETag remains stable across
// replicas and restarts, so every pod presents the same cache identity.
func serveBytes(w http.ResponseWriter, r *http.Request, name string, data []byte, cacheControl string) {
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("ETag", etag)
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

// securityHeaders enforces the browser-security baseline at the origin as
// defense in depth if an edge rule is later changed. HSTS is deliberately scoped
// to this hostname rather than making a promise for every subdomain.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
