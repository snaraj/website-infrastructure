package releaseselector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	githubAPIBase    = "https://api.github.com"
	githubAPIVersion = "2026-03-10"
	maxAPIBytes      = 1024 * 1024
)

// RemoteSnapshot is a normalized, security-relevant GitHub observation.
type RemoteSnapshot struct {
	Absent         bool
	Bundle         []byte
	BundleAsset    assetRecord
	Commit         commitRecord
	Identity       []byte
	IdentityDigest string
	Asset          assetRecord
	Evidence       Evidence
	MainRun        workflowRun
	PlatformRun    workflowRun
	Release        releaseRecord
	Tag            tagRecord
	TagRef         tagRefRecord
}

// Equal reports whether two complete remote observations agree. API timestamps,
// URLs, and actor decoration never enter the normalized structures.
func (snapshot RemoteSnapshot) Equal(other RemoteSnapshot) bool {
	return reflect.DeepEqual(snapshot, other)
}

// RemoteReader performs one complete candidate observation.
type RemoteReader interface {
	Snapshot(context.Context, string, string, string, string, string) (RemoteSnapshot, error)
}

// GitHubClient is an unauthenticated, fixed-origin GitHub REST client.
type GitHubClient struct {
	client      *http.Client
	assetClient *http.Client
	base        *url.URL
	verifier    BundleVerifier
}

// NewGitHubClient constructs the credential-free fixed-origin client.
func NewGitHubClient() (*GitHubClient, error) {
	base, err := url.Parse(githubAPIBase)
	if err != nil {
		return nil, fmt.Errorf("parse fixed GitHub API origin: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.ResponseHeaderTimeout = 20 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	apiClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("GitHub API redirects are forbidden")
		},
	}
	assetTransport := transport.Clone()
	return &GitHubClient{
		base:     base,
		client:   apiClient,
		verifier: newCosignBundleVerifier(),
		assetClient: &http.Client{
			Transport:     assetTransport,
			Timeout:       30 * time.Second,
			CheckRedirect: assetRedirectPolicy,
		},
	}, nil
}

func assetRedirectPolicy(request *http.Request, via []*http.Request) error {
	port := request.URL.Port()
	if len(via) > 3 || request.URL.Scheme != "https" || request.URL.User != nil ||
		(port != "" && port != "443") || !allowedAssetHost(request.URL.Hostname()) {
		return fmt.Errorf("release asset redirect left the fixed HTTPS host set")
	}
	request.Header.Del("Authorization")
	return nil
}

func allowedAssetHost(host string) bool {
	return host == "api.github.com" || host == "release-assets.githubusercontent.com" || host == "objects.githubusercontent.com"
}

type releaseRecord struct {
	Assets          []assetRecord `json:"assets"`
	Author          releaseAuthor `json:"author"`
	Draft           bool          `json:"draft"`
	ID              int64         `json:"id"`
	Immutable       bool          `json:"immutable"`
	Name            string        `json:"name"`
	Prerelease      bool          `json:"prerelease"`
	TagName         string        `json:"tag_name"`
	TargetCommitish string        `json:"target_commitish"`
}

type assetRecord struct {
	BrowserDownloadURL string `json:"browser_download_url"`
	ContentType        string `json:"content_type"`
	Digest             string `json:"digest"`
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	State              string `json:"state"`
	URL                string `json:"url"`
}

type releaseAuthor struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type tagRefRecord struct {
	Object gitObject `json:"object"`
	Ref    string    `json:"ref"`
}

type tagRecord struct {
	Object gitObject `json:"object"`
	SHA    string    `json:"sha"`
	Tag    string    `json:"tag"`
}

type gitObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}

type commitRecord struct {
	SHA  string    `json:"sha"`
	Tree gitObject `json:"tree"`
}

type workflowRun struct {
	Conclusion string        `json:"conclusion"`
	Event      string        `json:"event"`
	HeadBranch string        `json:"head_branch"`
	HeadSHA    string        `json:"head_sha"`
	ID         int64         `json:"id"`
	Path       string        `json:"path"`
	Repository runRepository `json:"repository"`
	RunAttempt int64         `json:"run_attempt"`
	Status     string        `json:"status"`
}

type runRepository struct {
	FullName string `json:"full_name"`
}

// Snapshot reads the exact release and annotated tag, then the two exact run
// attempts named by the canonical identity asset. It never lists or picks a "latest"
// workflow run, so duplicate and arbitrary higher runs cannot win a race.
func (client *GitHubClient) Snapshot(ctx context.Context, currentTag, currentSHA, candidateTag, imageDigest, imageBuildSHA string) (RemoteSnapshot, error) {
	var snapshot RemoteSnapshot
	releaseStatus, err := client.get(ctx, "/repos/"+Repository+"/releases/tags/"+url.PathEscape(candidateTag), &snapshot.Release)
	if err != nil {
		return snapshot, err
	}
	refStatus, err := client.get(ctx, "/repos/"+Repository+"/git/ref/tags/"+url.PathEscape(candidateTag), &snapshot.TagRef)
	if err != nil {
		return snapshot, err
	}
	if releaseStatus == http.StatusNotFound && refStatus == http.StatusNotFound {
		snapshot.Absent = true
		return snapshot, nil
	}
	if releaseStatus != http.StatusOK || refStatus != http.StatusOK {
		return snapshot, fmt.Errorf("candidate %s is partial or returned a non-authoritative status", SafeTag(candidateTag))
	}
	if snapshot.TagRef.Ref != "refs/tags/"+candidateTag || snapshot.TagRef.Object.Type != "tag" || !shaRE.MatchString(snapshot.TagRef.Object.SHA) {
		return snapshot, fmt.Errorf("candidate %s is not an annotated tag ref", SafeTag(candidateTag))
	}

	snapshot.Asset, snapshot.BundleAsset, err = releaseAssets(&snapshot.Release, candidateTag)
	if err != nil {
		return snapshot, fmt.Errorf("candidate %s: %w", SafeTag(candidateTag), err)
	}
	identity, err := client.getAsset(ctx, snapshot.Asset.ID, maxEvidenceBytes)
	if err != nil {
		return snapshot, fmt.Errorf("candidate %s: %w", SafeTag(candidateTag), err)
	}
	bundle, err := client.getAsset(ctx, snapshot.BundleAsset.ID, maxBundleBytes)
	if err != nil {
		return snapshot, fmt.Errorf("candidate %s: %w", SafeTag(candidateTag), err)
	}
	evidence, identityDigest, err := ParseIdentity(identity, currentTag, currentSHA, candidateTag, imageDigest, imageBuildSHA)
	if err != nil {
		return snapshot, fmt.Errorf("candidate %s: %w", SafeTag(candidateTag), err)
	}
	if int64(len(identity)) != snapshot.Asset.Size || identityDigest != snapshot.Asset.Digest {
		return snapshot, fmt.Errorf("candidate %s identity asset metadata conflicts with its bytes", SafeTag(candidateTag))
	}
	if int64(len(bundle)) != snapshot.BundleAsset.Size || bytesDigest(bundle) != snapshot.BundleAsset.Digest {
		return snapshot, fmt.Errorf("candidate %s Sigstore bundle metadata conflicts with its bytes", SafeTag(candidateTag))
	}
	if client.verifier == nil {
		return snapshot, fmt.Errorf("candidate %s Sigstore verifier is unavailable", SafeTag(candidateTag))
	}
	if err := client.verifier.Verify(ctx, identity, bundle); err != nil {
		return snapshot, fmt.Errorf("candidate %s: %w", SafeTag(candidateTag), err)
	}
	snapshot.Identity = append([]byte(nil), identity...)
	snapshot.Bundle = append([]byte(nil), bundle...)
	snapshot.IdentityDigest = identityDigest
	snapshot.Evidence = evidence

	tagStatus, err := client.get(ctx, "/repos/"+Repository+"/git/tags/"+snapshot.TagRef.Object.SHA, &snapshot.Tag)
	if err != nil || tagStatus != http.StatusOK {
		if err != nil {
			return snapshot, err
		}
		return snapshot, fmt.Errorf("candidate %s annotated tag object is unavailable", SafeTag(candidateTag))
	}
	if err := validateRESTRecords(snapshot); err != nil {
		return snapshot, err
	}
	commitStatus, err := client.get(ctx, "/repos/"+Repository+"/git/commits/"+evidence.Source.MergeSHA, &snapshot.Commit)
	if err != nil || commitStatus != http.StatusOK {
		if err != nil {
			return snapshot, err
		}
		return snapshot, fmt.Errorf("protected source commit is unavailable")
	}
	if snapshot.Commit.SHA != evidence.Source.MergeSHA || snapshot.Commit.Tree.SHA != evidence.Source.TreeSHA || !shaRE.MatchString(snapshot.Commit.Tree.SHA) {
		return snapshot, fmt.Errorf("protected source tree conflicts with release identity")
	}

	mainPath := workflowAttemptPath(evidence.MainCI.RunID, evidence.MainCI.RunAttempt)
	mainStatus, err := client.get(ctx, mainPath, &snapshot.MainRun)
	if err != nil || mainStatus != http.StatusOK {
		if err != nil {
			return snapshot, err
		}
		return snapshot, fmt.Errorf("main CI attempt is unavailable")
	}
	platformPath := workflowAttemptPath(evidence.PlatformRelease.RunID, evidence.PlatformRelease.RunAttempt)
	platformStatus, err := client.get(ctx, platformPath, &snapshot.PlatformRun)
	if err != nil || platformStatus != http.StatusOK {
		if err != nil {
			return snapshot, err
		}
		return snapshot, fmt.Errorf("platform release attempt is unavailable")
	}
	if err := validateRunRecord(snapshot.MainRun, evidence.MainCI); err != nil {
		return snapshot, fmt.Errorf("main CI REST record: %w", err)
	}
	if err := validateRunRecord(snapshot.PlatformRun, evidence.PlatformRelease); err != nil {
		return snapshot, fmt.Errorf("platform release REST record: %w", err)
	}
	return snapshot, nil
}

func releaseAssets(release *releaseRecord, tag string) (assetRecord, assetRecord, error) {
	if release == nil || len(release.Assets) != 2 {
		return assetRecord{}, assetRecord{}, fmt.Errorf("release must carry exactly the identity and Sigstore bundle assets")
	}
	sort.Slice(release.Assets, func(left, right int) bool {
		return release.Assets[left].Name < release.Assets[right].Name
	})
	var identity, bundle assetRecord
	for _, asset := range release.Assets {
		switch asset.Name {
		case IdentityAssetName:
			identity = asset
		case IdentityBundleAssetName:
			bundle = asset
		default:
			return assetRecord{}, assetRecord{}, fmt.Errorf("release carries a foreign asset")
		}
	}
	if err := validateAssetRecord(identity, tag); err != nil {
		return assetRecord{}, assetRecord{}, err
	}
	if err := validateBundleAssetRecord(bundle, tag); err != nil {
		return assetRecord{}, assetRecord{}, err
	}
	return identity, bundle, nil
}

func workflowAttemptPath(runID, attempt int64) string {
	return "/repos/" + Repository + "/actions/runs/" + strconv.FormatInt(runID, 10) + "/attempts/" + strconv.FormatInt(attempt, 10)
}

func validateRESTRecords(snapshot RemoteSnapshot) error {
	evidence := snapshot.Evidence
	if snapshot.Release.ID != evidence.Release.ID || snapshot.Release.TagName != evidence.Release.TagName || snapshot.Release.TargetCommitish != evidence.Release.TargetCommitish || snapshot.Release.Name != "Platform "+evidence.Release.TagName {
		return fmt.Errorf("GitHub Release REST identity conflicts with its identity asset")
	}
	if snapshot.Release.Draft != evidence.Release.Draft || snapshot.Release.Immutable != evidence.Release.Immutable || snapshot.Release.Prerelease != evidence.Release.Prerelease || int64(len(snapshot.Release.Assets)) != evidence.Release.AssetCount {
		return fmt.Errorf("GitHub Release REST state conflicts with its identity asset")
	}
	if snapshot.Release.Author.Login != "github-actions[bot]" || snapshot.Release.Author.ID != 41898282 {
		return fmt.Errorf("GitHub Release author is foreign")
	}
	if snapshot.TagRef.Object.SHA != evidence.Tag.ObjectSHA || snapshot.Tag.SHA != evidence.Tag.ObjectSHA || snapshot.Tag.Tag != evidence.Tag.Name || snapshot.Tag.Object.Type != "commit" || snapshot.Tag.Object.SHA != evidence.Tag.PeeledCommit {
		return fmt.Errorf("annotated tag REST state conflicts with release identity")
	}
	return nil
}

func validateAssetRecord(asset assetRecord, tag string) error {
	return validateNamedAssetRecord(asset, tag, IdentityAssetName, maxEvidenceBytes)
}

func validateBundleAssetRecord(asset assetRecord, tag string) error {
	return validateNamedAssetRecord(asset, tag, IdentityBundleAssetName, maxBundleBytes)
}

func validateNamedAssetRecord(asset assetRecord, tag, name string, limit int) error {
	if asset.ID <= 0 || asset.Name != name || asset.State != "uploaded" || asset.ContentType != "application/json" || asset.Size <= 0 || asset.Size > int64(limit) || !ValidDigest(asset.Digest) {
		return fmt.Errorf("release identity asset metadata is incomplete or foreign")
	}
	expectedAPI := githubAPIBase + "/repos/" + Repository + "/releases/assets/" + strconv.FormatInt(asset.ID, 10)
	expectedDownload := "https://github.com/" + Repository + "/releases/download/" + tag + "/" + name
	if asset.URL != expectedAPI || asset.BrowserDownloadURL != expectedDownload {
		return fmt.Errorf("release identity asset URL is foreign")
	}
	return nil
}

func bytesDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateRunRecord(actual workflowRun, expected RunEvidence) error {
	if actual.ID != expected.RunID || actual.RunAttempt != expected.RunAttempt || actual.Path != expected.Workflow || actual.Event != expected.Event || actual.HeadBranch != "main" || actual.HeadSHA != expected.HeadSHA || actual.Repository.FullName != Repository {
		return fmt.Errorf("attempt %s is foreign", canonicalRunKey(expected))
	}
	if actual.Status != "completed" || actual.Conclusion != "success" {
		return fmt.Errorf("attempt %s did not complete successfully", canonicalRunKey(expected))
	}
	return nil
}

func (client *GitHubClient) get(ctx context.Context, path string, output any) (int, error) {
	if !strings.HasPrefix(path, "/repos/"+Repository+"/") || strings.Contains(path, "..") {
		return 0, fmt.Errorf("GitHub API path is outside the fixed repository")
	}
	endpoint := client.base.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("construct GitHub API request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	request.Header.Set("User-Agent", "snaraj-platform-release-selector/1")
	response, err := client.client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("GitHub API read failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, maxAPIBytes+1)); err != nil {
			return 0, fmt.Errorf("drain GitHub API 404: %w", err)
		}
		return response.StatusCode, nil
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxAPIBytes+1))
		return response.StatusCode, fmt.Errorf("GitHub API returned HTTP %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxAPIBytes+1))
	if err != nil {
		return 0, fmt.Errorf("read GitHub API response: %w", err)
	}
	if len(payload) > maxAPIBytes {
		return 0, fmt.Errorf("GitHub API response exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(output); err != nil {
		return 0, fmt.Errorf("decode GitHub API response: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return 0, fmt.Errorf("GitHub API response: %w", err)
	}
	return response.StatusCode, nil
}

func (client *GitHubClient) getAsset(ctx context.Context, assetID int64, limit int) ([]byte, error) {
	if assetID <= 0 || limit <= 0 || limit > maxBundleBytes {
		return nil, fmt.Errorf("release identity asset ID is invalid")
	}
	path := "/repos/" + Repository + "/releases/assets/" + strconv.FormatInt(assetID, 10)
	endpoint := client.base.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("construct identity asset request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	request.Header.Set("User-Agent", "snaraj-platform-release-selector/1")
	response, err := client.assetClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download identity asset: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, int64(limit)+1))
		return nil, fmt.Errorf("identity asset download returned HTTP %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read identity asset: %w", err)
	}
	if len(payload) == 0 || len(payload) > limit {
		return nil, fmt.Errorf("identity asset size is invalid")
	}
	return payload, nil
}
