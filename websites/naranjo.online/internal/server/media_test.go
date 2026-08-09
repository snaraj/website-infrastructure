package server

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// testMediaDigest matches the tiny immutable fixture so the test never models
// a content-addressed path whose bytes violate its publication checksum.
var testMediaDigest = fmt.Sprintf("%x", sha256.Sum256([]byte("0123456789")))

// mediaFixture creates only tiny protocol fixtures; it never approximates
// production media size because streaming behavior comes from an open os.File,
// not from loading test data into the application.
func mediaFixture(t *testing.T) (*Site, string) {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{
		filepath.Join(root, "immutable", testMediaDigest),
		filepath.Join(root, "mutable"),
		filepath.Join(root, "mutable", "album"),
	} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
	}
	files := map[string]string{
		filepath.Join(root, "immutable", testMediaDigest, "clip.mp4"): "0123456789",
		filepath.Join(root, "mutable", "song.flac"):                   "fLaCdata",
		filepath.Join(root, "mutable", "unknown.bin"):                 "opaque",
	}
	modified := time.Unix(1_700_000_000, 0).UTC()
	for name, content := range files {
		if err := os.WriteFile(name, []byte(content), 0o640); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if err := os.Chtimes(name, modified, modified); err != nil {
			t.Fatalf("Chtimes() error = %v", err)
		}
	}

	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<!doctype html><h1>Hello World!</h1>")}}
	site, err := NewWithMedia(assets, MediaOptions{Root: root, MaxConcurrent: 2})
	if err != nil {
		t.Fatalf("NewWithMedia() error = %v", err)
	}
	t.Cleanup(func() {
		if err := site.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return site, root
}

// mediaRequest executes one request through the complete site so tests cover
// pre-routing path rejection and the same security headers used in production.
func mediaRequest(t *testing.T, site http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	site.ServeHTTP(response, request)
	return response
}

// TestMediaFullHeadAndRange locks in streaming-friendly HTTP semantics for
// complete downloads, metadata-only probes, and video/audio seeking.
func TestMediaFullHeadAndRange(t *testing.T) {
	site, _ := mediaFixture(t)
	target := "/media/immutable/" + testMediaDigest + "/clip.mp4"

	full := mediaRequest(t, site, http.MethodGet, target, nil)
	if full.Code != http.StatusOK || full.Body.String() != "0123456789" {
		t.Fatalf("full response = %d %q", full.Code, full.Body.String())
	}
	for name, want := range map[string]string{
		"Accept-Ranges":  "bytes",
		"Cache-Control":  "public, max-age=31536000, immutable",
		"Content-Length": "10",
		"Content-Type":   "video/mp4",
		"ETag":           `"` + testMediaDigest + `"`,
	} {
		if got := full.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if full.Header().Get("Last-Modified") == "" {
		t.Error("Last-Modified is missing")
	}

	head := mediaRequest(t, site, http.MethodHead, target, nil)
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != "10" {
		t.Fatalf("HEAD = %d len=%d Content-Length=%q", head.Code, head.Body.Len(), head.Header().Get("Content-Length"))
	}

	partial := mediaRequest(t, site, http.MethodGet, target, map[string]string{"Range": "bytes=2-5"})
	if partial.Code != http.StatusPartialContent || partial.Body.String() != "2345" {
		t.Fatalf("range response = %d %q", partial.Code, partial.Body.String())
	}
	if got := partial.Header().Get("Content-Range"); got != "bytes 2-5/10" {
		t.Errorf("Content-Range = %q", got)
	}
}

// TestMediaConditionalRequests verifies strong immutable validation, standard
// If-Range handling, and collision-free no-store behavior for mutable aliases.
func TestMediaConditionalRequests(t *testing.T) {
	site, root := mediaFixture(t)
	immutableTarget := "/media/immutable/" + testMediaDigest + "/clip.mp4"
	immutable := mediaRequest(t, site, http.MethodGet, immutableTarget, nil)
	notModified := mediaRequest(t, site, http.MethodGet, immutableTarget, map[string]string{"If-None-Match": immutable.Header().Get("ETag")})
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
		t.Fatalf("immutable conditional = %d len=%d", notModified.Code, notModified.Body.Len())
	}

	mutableTarget := "/media/mutable/song.flac"
	mutable := mediaRequest(t, site, http.MethodGet, mutableTarget, nil)
	if got := mutable.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("mutable Cache-Control = %q", got)
	}
	if mutable.Header().Get("ETag") != "" || mutable.Header().Get("Last-Modified") != "" {
		t.Fatalf("mutable validators must be absent: ETag=%q Last-Modified=%q", mutable.Header().Get("ETag"), mutable.Header().Get("Last-Modified"))
	}
	mutablePath := filepath.Join(root, "mutable", "song.flac")
	originalInfo, err := os.Stat(mutablePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mutablePath, []byte("fLaCnext"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(mutablePath, originalInfo.ModTime(), originalInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	replaced := mediaRequest(t, site, http.MethodGet, mutableTarget, map[string]string{
		"If-None-Match":     `W/"stale-metadata-validator"`,
		"If-Modified-Since": originalInfo.ModTime().UTC().Format(http.TimeFormat),
	})
	if replaced.Code != http.StatusOK || replaced.Body.String() != "fLaCnext" {
		t.Fatalf("same-size mutable replacement = %d %q", replaced.Code, replaced.Body.String())
	}
	ifRange := mediaRequest(t, site, http.MethodGet, immutableTarget, map[string]string{
		"If-Range": immutable.Header().Get("ETag"),
		"Range":    "bytes=8-",
	})
	if ifRange.Code != http.StatusPartialContent || ifRange.Body.String() != "89" {
		t.Fatalf("If-Range = %d %q", ifRange.Code, ifRange.Body.String())
	}
}

// TestMediaRangeFailures keeps malformed, unsatisfiable, and abusive multipart
// requests at one deterministic status without allocating media-sized buffers.
func TestMediaRangeFailures(t *testing.T) {
	site, _ := mediaFixture(t)
	target := "/media/immutable/" + testMediaDigest + "/clip.mp4"
	manyParts := "bytes=" + strings.Repeat("0-0,", maxRangeParts) + "0-0"
	oversized := "bytes=" + strings.Repeat("0", maxRangeHeaderBytes)
	for name, value := range map[string]string{
		"malformed":     "bytes=nope",
		"unsatisfiable": "bytes=999-",
		"too many":      manyParts,
		"too long":      oversized,
	} {
		t.Run(name, func(t *testing.T) {
			response := mediaRequest(t, site, http.MethodGet, target, map[string]string{"Range": value})
			if response.Code != http.StatusRequestedRangeNotSatisfiable {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}

	current := mediaRequest(t, site, http.MethodGet, target, nil)
	notModified := mediaRequest(t, site, http.MethodGet, target, map[string]string{
		"If-None-Match": current.Header().Get("ETag"),
		"Range":         manyParts,
	})
	if notModified.Code != http.StatusNotModified {
		t.Fatalf("conditional abusive range = %d, want 304", notModified.Code)
	}
	ifRangeMiss := mediaRequest(t, site, http.MethodGet, target, map[string]string{
		"If-Range": `"different"`,
		"Range":    manyParts,
	})
	if ifRangeMiss.Code != http.StatusOK || ifRangeMiss.Body.String() != "0123456789" {
		t.Fatalf("mismatched If-Range = %d %q", ifRangeMiss.Code, ifRangeMiss.Body.String())
	}
	ifRangeMatch := mediaRequest(t, site, http.MethodGet, target, map[string]string{
		"If-Range": current.Header().Get("ETag"),
		"Range":    manyParts,
	})
	if ifRangeMatch.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("matching If-Range abusive range = %d, want 416", ifRangeMatch.Code)
	}
}

// TestMediaPathBoundary proves that traversal, hidden/internal material,
// directory indexes, alternate namespaces, and missing files all stay opaque.
func TestMediaPathBoundary(t *testing.T) {
	site, _ := mediaFixture(t)
	for name, target := range map[string]string{
		"traversal":         "/media/../index.html",
		"encoded traversal": "/media/%2e%2e/index.html",
		"backslash":         "/media/mutable/album%5csecret.jpg",
		"dotfile":           "/media/mutable/.secret",
		"internal":          "/media/mutable/metadata/file.json",
		"directory":         "/media/mutable/album",
		"unknown class":     "/media/originals/file.flac",
		"missing":           "/media/mutable/missing.flac",
	} {
		t.Run(name, func(t *testing.T) {
			response := mediaRequest(t, site, http.MethodGet, target, nil)
			if response.Code != http.StatusNotFound {
				t.Fatalf("status = %d Location=%q", response.Code, response.Header().Get("Location"))
			}
		})
	}
}

// TestMediaSymlinkIsOpaque ensures neither a file link nor an intermediate
// directory link can expose data outside the reviewed delivery tree.
func TestMediaSymlinkIsOpaque(t *testing.T) {
	site, root := mediaFixture(t)
	outside := filepath.Join(t.TempDir(), "outside.mp4")
	if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(root, "mutable", "linked.mp4")
	if err := os.Symlink(outside, fileLink); err != nil {
		t.Skipf("symlink creation is unavailable on this test host: %v", err)
	}
	outsideDirectory := filepath.Dir(outside)
	directoryLink := filepath.Join(root, "mutable", "linked-directory")
	if err := os.Symlink(outsideDirectory, directoryLink); err != nil {
		t.Skipf("directory symlink creation is unavailable on this test host: %v", err)
	}
	for _, target := range []string{
		"/media/mutable/linked.mp4",
		"/media/mutable/linked-directory/outside.mp4",
	} {
		response := mediaRequest(t, site, http.MethodGet, target, nil)
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "private") {
			t.Fatalf("symlink response = %d %q", response.Code, response.Body.String())
		}
	}
}

// TestMediaHardLinkIsOpaque proves the Linux origin will not serve an inode
// that is also reachable from an originals or staging path outside the root.
func TestMediaHardLinkIsOpaque(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production hard-link enforcement is Linux-specific")
	}
	site, root := mediaFixture(t)
	original := filepath.Join(t.TempDir(), "original.flac")
	if err := os.WriteFile(original, []byte("private original"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "mutable", "hard-linked.flac")
	if err := os.Link(original, linked); err != nil {
		t.Skipf("hard-link creation is unavailable on this filesystem: %v", err)
	}
	response := mediaRequest(t, site, http.MethodGet, "/media/mutable/hard-linked.flac", nil)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "private original") {
		t.Fatalf("hard-link response = %d %q", response.Code, response.Body.String())
	}
}

// TestMediaMIMETypes uses explicit expected values so host MIME registries
// cannot make security behavior differ between CI and the Pi.
func TestMediaMIMETypes(t *testing.T) {
	site, root := mediaFixture(t)
	for extension, want := range map[string]string{
		".avif": "image/avif",
		".flac": "audio/flac",
		".gif":  "image/gif",
		".jpeg": "image/jpeg",
		".jpg":  "image/jpeg",
		".mp4":  "video/mp4",
		".png":  "image/png",
		".webm": "video/webm",
		".webp": "image/webp",
	} {
		name := "sample" + extension
		if err := os.WriteFile(filepath.Join(root, "mutable", name), []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
		response := mediaRequest(t, site, http.MethodGet, "/media/mutable/"+name, nil)
		if got := response.Header().Get("Content-Type"); got != want {
			t.Errorf("%s Content-Type = %q, want %q", extension, got, want)
		}
	}

	unknown := mediaRequest(t, site, http.MethodGet, "/media/mutable/unknown.bin", nil)
	if got := unknown.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("unknown Content-Type = %q", got)
	}
	if got := unknown.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "attachment;") {
		t.Errorf("unknown Content-Disposition = %q", got)
	}
	if got := unknown.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
}

// TestMediaCapacityRejectsImmediately exercises the fail-closed overload path
// without creating long transfers or depending on scheduler timing.
func TestMediaCapacityRejectsImmediately(t *testing.T) {
	root := t.TempDir()
	media, err := openMediaHandler(MediaOptions{Root: root, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = media.Close() })
	media.slots <- struct{}{}
	response := httptest.NewRecorder()
	media.ServeHTTP(response, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/media/immutable/%s/missing.mp4", testMediaDigest), nil))
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") == "" {
		t.Fatalf("capacity response = %d Retry-After=%q", response.Code, response.Header().Get("Retry-After"))
	}
	<-media.slots
}

// TestMediaRemainsAbsentByDefault proves the ordinary application constructor
// reserves the media namespace even if a build accidentally embeds matching
// files, preventing fallthrough around the bounded media handler.
func TestMediaRemainsAbsentByDefault(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":              &fstest.MapFile{Data: []byte("index")},
		"media/mutable/song.flac": &fstest.MapFile{Data: []byte("must stay private")},
	}
	site, err := New(assets)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/media", "/media/", "/media/mutable/song.flac"} {
		response := mediaRequest(t, site, http.MethodGet, target, nil)
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "must stay private") {
			t.Fatalf("disabled media %q = %d %q", target, response.Code, response.Body.String())
		}
	}
}
