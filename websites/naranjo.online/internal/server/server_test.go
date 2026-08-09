// Package server tests the origin HTTP contract independently from the frontend
// toolchain by supplying a small in-memory filesystem.
package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// testHandler builds the production handler around deterministic in-memory
// files, isolating HTTP policy tests from frontend compilation details.
func testHandler(t *testing.T) http.Handler {
	t.Helper()
	assets := fstest.MapFS{
		"index.html":        &fstest.MapFile{Data: []byte("<!doctype html><h1>Hello World!</h1>")},
		"assets/app-abc.js": &fstest.MapFile{Data: []byte("console.log('hello')")},
		".gitkeep":          &fstest.MapFile{Data: []byte("build placeholder")},
	}
	var filesystem fs.FS = assets
	siteHandler, err := New(filesystem)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return siteHandler
}

// TestRootAndSecurityHeaders protects the uncached document response and the
// browser-security baseline that must remain present behind Cloudflare.
func TestRootAndSecurityHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://example.invalid/", nil)
	response := httptest.NewRecorder()
	testHandler(t).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Hello World!") {
		t.Fatalf("body does not contain Hello World!: %q", response.Body.String())
	}
	for _, header := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"} {
		if response.Header().Get(header) == "" {
			t.Errorf("missing header %s", header)
		}
	}
	if got := response.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("Strict-Transport-Security = %q", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

// TestAssetCachingAndConditionalRequest verifies that hashed assets are durable
// cache entries while still participating in standard conditional requests.
func TestAssetCachingAndConditionalRequest(t *testing.T) {
	siteHandler := testHandler(t)
	first := httptest.NewRecorder()
	siteHandler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/assets/app-abc.js", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d", first.Code)
	}
	if got := first.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", got)
	}
	secondRequest := httptest.NewRequest(http.MethodGet, "/assets/app-abc.js", nil)
	secondRequest.Header.Set("If-None-Match", first.Header().Get("ETag"))
	second := httptest.NewRecorder()
	siteHandler.ServeHTTP(second, secondRequest)
	if second.Code != http.StatusNotModified {
		t.Fatalf("conditional status = %d", second.Code)
	}
}

// TestAssetRFCPreconditions delegates nuanced validator semantics to net/http
// and locks in the weak, list, wildcard, and failed-precondition cases we rely on.
func TestAssetRFCPreconditions(t *testing.T) {
	siteHandler := testHandler(t)
	initial := httptest.NewRecorder()
	siteHandler.ServeHTTP(initial, httptest.NewRequest(http.MethodGet, "/assets/app-abc.js", nil))
	etag := initial.Header().Get("ETag")
	if etag == "" {
		t.Fatal("initial response has no ETag")
	}

	for name, value := range map[string]string{
		"weak validator":     "W/" + etag,
		"validator list":     `"stale", ` + etag,
		"any representation": "*",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/assets/app-abc.js", nil)
			request.Header.Set("If-None-Match", value)
			response := httptest.NewRecorder()
			siteHandler.ServeHTTP(response, request)
			if response.Code != http.StatusNotModified {
				t.Fatalf("status = %d for If-None-Match %q", response.Code, value)
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/assets/app-abc.js", nil)
	request.Header.Set("If-Match", `"stale"`)
	response := httptest.NewRecorder()
	siteHandler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d for a failed If-Match", response.Code)
	}
}

// TestHealthMethodsAndMissingPath keeps probes read-only and confirms that
// unknown, traversal, and repository-placeholder paths are never served.
func TestHealthMethodsAndMissingPath(t *testing.T) {
	siteHandler := testHandler(t)
	for _, endpoint := range []string{"/livez", "/readyz"} {
		response := httptest.NewRecorder()
		siteHandler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, endpoint, nil))
		if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
			t.Errorf("%s = %d %q", endpoint, response.Code, response.Body.String())
		}
	}
	post := httptest.NewRecorder()
	siteHandler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/", nil))
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST = %d Allow=%q", post.Code, post.Header().Get("Allow"))
	}
	missing := httptest.NewRecorder()
	siteHandler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if missing.Code != http.StatusNotFound {
		t.Errorf("missing status = %d", missing.Code)
	}
	placeholder := httptest.NewRecorder()
	siteHandler.ServeHTTP(placeholder, httptest.NewRequest(http.MethodGet, "/.gitkeep", nil))
	if placeholder.Code != http.StatusNotFound {
		t.Errorf(".gitkeep status = %d", placeholder.Code)
	}
	traversal := httptest.NewRecorder()
	direct := &handler{assets: fstest.MapFS{}, index: []byte("index")}
	direct.ServeHTTP(traversal, httptest.NewRequest(http.MethodGet, "/../index.html", nil))
	if traversal.Code != http.StatusNotFound {
		t.Errorf("traversal status = %d", traversal.Code)
	}
}
