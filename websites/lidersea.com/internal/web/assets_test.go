// Package web_test verifies the real cross-package artifact boundary: the
// frontend built by Vite must be embedded and servable by the Go HTTP package.
package web_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/snaraj/website-infrastructure/websites/lidersea.com/internal/server"
	website "github.com/snaraj/website-infrastructure/websites/lidersea.com/internal/web"
)

// builtAssetReference finds Vite's content-addressed script and stylesheet URLs
// without coupling the test to hashes that legitimately change on every build.
var builtAssetReference = regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`)

// TestBuiltFrontendIsEmbeddedAndServed proves that CI is testing the production
// bundle, its immutable assets, and both lines of the static application fallback.
func TestBuiltFrontendIsEmbeddedAndServed(t *testing.T) {
	assets, err := website.FileSystem()
	if err != nil {
		t.Fatalf("FileSystem() error = %v", err)
	}
	siteHandler, err := server.New(assets)
	if err != nil {
		t.Fatalf("server.New() error = %v; run the pinned frontend build before Go tests", err)
	}

	root := httptest.NewRecorder()
	siteHandler.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Code != http.StatusOK {
		t.Fatalf("root status = %d", root.Code)
	}
	body := root.Body.String()
	for _, required := range []string{"data-static-fallback", "Hello World!", "Website coming soon!"} {
		if !strings.Contains(body, required) {
			t.Fatalf("built root lacks %q: %q", required, body)
		}
	}
	if strings.Contains(body, "/src/main.ts") {
		t.Fatalf("built root still references a development entrypoint: %q", body)
	}

	references := builtAssetReference.FindAllStringSubmatch(body, -1)
	if len(references) < 2 {
		t.Fatalf("built root has fewer than two generated asset references: %q", body)
	}
	for _, reference := range references {
		asset := httptest.NewRecorder()
		siteHandler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, reference[1], nil))
		if asset.Code != http.StatusOK || asset.Body.Len() == 0 {
			t.Errorf("asset %s = status %d, %d bytes", reference[1], asset.Code, asset.Body.Len())
		}
		if got := asset.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("asset %s Cache-Control = %q", reference[1], got)
		}
	}

	placeholder := httptest.NewRecorder()
	siteHandler.ServeHTTP(placeholder, httptest.NewRequest(http.MethodGet, "/.gitkeep", nil))
	if placeholder.Code != http.StatusNotFound {
		t.Errorf("embedded .gitkeep status = %d", placeholder.Code)
	}
}
