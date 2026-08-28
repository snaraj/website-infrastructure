package releaseselector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func response(status int, body []byte, location string) *http.Response {
	header := make(http.Header)
	if location != "" {
		header.Set("Location", location)
	}
	return &http.Response{
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     header,
		StatusCode: status,
	}
}

func TestAssetDownloadAllowsOnlyBoundedCredentiallessGitHubRedirects(t *testing.T) {
	payload := canonicalEvidence(t, validEvidence())
	calls := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Header.Get("Authorization") != "" {
			return nil, fmt.Errorf("credential reached asset request")
		}
		switch request.URL.Hostname() {
		case "api.github.com":
			if request.Header.Get("Accept") != "application/octet-stream" {
				return nil, fmt.Errorf("asset media type is not exact")
			}
			return response(http.StatusFound, nil, "https://release-assets.githubusercontent.com/fixed-token"), nil
		case "release-assets.githubusercontent.com":
			return response(http.StatusOK, payload, ""), nil
		default:
			return nil, fmt.Errorf("unexpected host %s", request.URL.Hostname())
		}
	})
	base, _ := url.Parse(githubAPIBase)
	client := &GitHubClient{
		base: base,
		assetClient: &http.Client{
			Transport:     transport,
			CheckRedirect: assetRedirectPolicy,
		},
	}
	actual, err := client.getAsset(context.Background(), 400, maxEvidenceBytes)
	if err != nil || !bytes.Equal(actual, payload) || calls != 2 {
		t.Fatalf("unexpected asset download: calls=%d err=%v", calls, err)
	}
}

func TestAssetDownloadRejectsForeignRedirectAndOversizeBody(t *testing.T) {
	for name, handler := range map[string]roundTripFunc{
		"foreign redirect": func(_ *http.Request) (*http.Response, error) {
			return response(http.StatusFound, nil, "https://example.invalid/identity"), nil
		},
		"oversize body": func(_ *http.Request) (*http.Response, error) {
			return response(http.StatusOK, bytes.Repeat([]byte("x"), maxEvidenceBytes+1), ""), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			base, _ := url.Parse(githubAPIBase)
			client := &GitHubClient{
				base: base,
				assetClient: &http.Client{
					Transport:     handler,
					CheckRedirect: assetRedirectPolicy,
				},
			}
			if _, err := client.getAsset(context.Background(), 400, maxEvidenceBytes); err == nil {
				t.Fatal("hostile asset response was accepted")
			}
		})
	}
}

func TestAssetRedirectPolicyRejectsAmbiguousOrigins(t *testing.T) {
	for name, rawURL := range map[string]string{
		"cleartext":        "http://release-assets.githubusercontent.com/token",
		"foreign host":     "https://example.invalid/token",
		"nonstandard port": "https://release-assets.githubusercontent.com:444/token",
		"userinfo":         "https://@release-assets.githubusercontent.com/token",
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := url.Parse(rawURL)
			if err != nil {
				t.Fatal(err)
			}
			if err := assetRedirectPolicy(&http.Request{URL: parsed}, []*http.Request{{}}); err == nil {
				t.Fatal("ambiguous redirect origin was accepted")
			}
		})
	}
	parsed, _ := url.Parse("https://release-assets.githubusercontent.com/token")
	if err := assetRedirectPolicy(&http.Request{URL: parsed}, make([]*http.Request, 4)); err == nil {
		t.Fatal("unbounded redirect chain was accepted")
	}
}

func TestAssetMetadataIsExactAndSelfHashFree(t *testing.T) {
	asset := assetRecord{
		BrowserDownloadURL: "https://github.com/snaraj/website-infrastructure/releases/download/v0.1.41/" + IdentityAssetName,
		ContentType:        "application/json",
		Digest:             "sha256:" + strings.Repeat("a", 64),
		ID:                 400,
		Name:               IdentityAssetName,
		Size:               1024,
		State:              "uploaded",
		URL:                "https://api.github.com/repos/snaraj/website-infrastructure/releases/assets/400",
	}
	if err := validateAssetRecord(asset, testCandidateTag); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*assetRecord){
		"wrong name":       func(value *assetRecord) { value.Name = "identity.json" },
		"wrong media type": func(value *assetRecord) { value.ContentType = "application/octet-stream" },
		"foreign URL":      func(value *assetRecord) { value.URL = "https://example.invalid/asset" },
		"wrong tag URL": func(value *assetRecord) {
			value.BrowserDownloadURL = strings.ReplaceAll(value.BrowserDownloadURL, testCandidateTag, "v0.1.42")
		},
		"missing digest": func(value *assetRecord) { value.Digest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := asset
			mutate(&changed)
			if err := validateAssetRecord(changed, testCandidateTag); err == nil {
				t.Fatal("foreign asset metadata was accepted")
			}
		})
	}
}

func TestReleaseAssetSetIsExactlyIdentityAndSigstoreBundle(t *testing.T) {
	identity := assetRecord{
		BrowserDownloadURL: "https://github.com/snaraj/website-infrastructure/releases/download/v0.1.41/" + IdentityAssetName,
		ContentType:        "application/json", Digest: "sha256:" + strings.Repeat("a", 64), ID: 400,
		Name: IdentityAssetName, Size: 1024, State: "uploaded",
		URL: "https://api.github.com/repos/snaraj/website-infrastructure/releases/assets/400",
	}
	bundle := identity
	bundle.ID = 401
	bundle.Name = IdentityBundleAssetName
	bundle.URL = "https://api.github.com/repos/snaraj/website-infrastructure/releases/assets/401"
	bundle.BrowserDownloadURL = "https://github.com/snaraj/website-infrastructure/releases/download/v0.1.41/" + IdentityBundleAssetName
	for name, assets := range map[string][]assetRecord{
		"missing bundle":     {identity},
		"duplicate identity": {identity, identity},
		"foreign extra":      {identity, bundle, {Name: "foreign"}},
	} {
		t.Run(name, func(t *testing.T) {
			release := releaseRecord{Assets: assets}
			if _, _, err := releaseAssets(&release, testCandidateTag); err == nil {
				t.Fatal("foreign release asset set was accepted")
			}
		})
	}
	release := releaseRecord{Assets: []assetRecord{bundle, identity}}
	selectedIdentity, selectedBundle, err := releaseAssets(&release, testCandidateTag)
	if err != nil || selectedIdentity.Name != IdentityAssetName || selectedBundle.Name != IdentityBundleAssetName {
		t.Fatalf("exact asset set was rejected: %v", err)
	}
}

func TestReleaseNotesNeverEnterTheNormalizedSnapshot(t *testing.T) {
	var first, second releaseRecord
	if err := json.Unmarshal([]byte(`{"id":300,"body":"first"}`), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"id":300,"body":"hostile informational text"}`), &second); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("release notes entered the normalized trust snapshot")
	}
}
