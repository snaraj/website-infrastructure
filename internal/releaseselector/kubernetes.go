package releaseselector

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	GitRepositoryNamespace = "flux-system"
	GitRepositoryName      = "flux-system"
	NaranjoKustomization   = "naranjo-online-reconciler"
	LiderseaKustomization  = "lidersea-com-reconciler"
	FluxFinalizer          = "finalizers.fluxcd.io"

	AnnotationSchema              = "release-selector.platform.snaraj.dev/schema"
	AnnotationReleaseID           = "release-selector.platform.snaraj.dev/release-id"
	AnnotationReleaseTag          = "release-selector.platform.snaraj.dev/release-tag"
	AnnotationReleaseTargetSHA    = "release-selector.platform.snaraj.dev/release-target-sha"
	AnnotationTagObjectSHA        = "release-selector.platform.snaraj.dev/tag-object-sha"
	AnnotationMainCI              = "release-selector.platform.snaraj.dev/main-ci"
	AnnotationPlatformRelease     = "release-selector.platform.snaraj.dev/platform-release"
	AnnotationSelectorImageDigest = "release-selector.platform.snaraj.dev/selector-image-digest"
	AnnotationIdentitySHA256      = "release-selector.platform.snaraj.dev/identity-sha256"
)

const selectorAnnotationPrefix = "release-selector.platform.snaraj.dev/"

const ExpectedIgnore = `/*
!/kubernetes/
/kubernetes/*
!/kubernetes/websites/
/kubernetes/websites/*
!/kubernetes/websites/naranjo-online/
!/kubernetes/websites/naranjo-online/**
!/kubernetes/websites/lidersea-com/
!/kubernetes/websites/lidersea-com/**
`

var (
	runPairRE              = regexp.MustCompile(`^[1-9][0-9]*/[1-9][0-9]*$`)
	dnsNameRE              = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`)
	evidenceAnnotationKeys = []string{
		AnnotationSchema,
		AnnotationReleaseID,
		AnnotationReleaseTag,
		AnnotationReleaseTargetSHA,
		AnnotationTagObjectSHA,
		AnnotationMainCI,
		AnnotationPlatformRelease,
		AnnotationSelectorImageDigest,
		AnnotationIdentitySHA256,
	}
)

// ClusterReaderWriter is the selector's entire Kubernetes authority.
type ClusterReaderWriter interface {
	GetGitRepository(context.Context) (GitRepository, error)
	GetKustomization(context.Context, string) (Kustomization, error)
	PatchGitRepository(context.Context, []JSONPatchOperation) (GitRepository, error)
}

// ErrConflict asks the coordinator to discard its patch and infer the phase
// again from fresh reads. It represents HTTP 409 and the exact generic HTTP
// 422 Status Kubernetes emits when an RFC 6902 test operation loses its race.
// The stale payload is never retried.
var ErrConflict = errors.New("Kubernetes compare-and-swap conflict")

const genericPatchRejection = "the server rejected our request due to an error in our request"

// JSONPatchOperation is one RFC 6902 operation. Selector patches are built
// only by the closed constructors in coordination.go.
type JSONPatchOperation struct {
	Operation string `json:"op"`
	Path      string `json:"path"`
	Value     any    `json:"value,omitempty"`
}

// kubernetesStatus is the exact generic Status envelope produced by
// NewGenericServerResponse for a JSON Patch application failure. Details and
// metadata are retained as raw JSON so a cause-bearing or otherwise widened
// 422 cannot be misclassified as compare-and-swap staleness.
type kubernetesStatus struct {
	APIVersion string          `json:"apiVersion"`
	Code       int             `json:"code"`
	Details    json.RawMessage `json:"details"`
	Kind       string          `json:"kind"`
	Message    string          `json:"message"`
	Metadata   json.RawMessage `json:"metadata"`
	Reason     string          `json:"reason"`
	Status     string          `json:"status"`
}

// GitRepository is the closed subset of the Flux v1 object used by this
// selector. Unknown top-level, metadata, spec, or status fields are rejected.
type GitRepository struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ObjectMeta        `json:"metadata"`
	Spec       GitRepositorySpec `json:"spec"`
	Status     json.RawMessage   `json:"status,omitempty"`
}

// ObjectMeta includes every ordinary server field seen on a namespaced CR.
type ObjectMeta struct {
	Annotations             map[string]string `json:"annotations,omitempty"`
	CreationTimestamp       string            `json:"creationTimestamp,omitempty"`
	DeletionGracePeriodSecs *int64            `json:"deletionGracePeriodSeconds,omitempty"`
	DeletionTimestamp       *string           `json:"deletionTimestamp,omitempty"`
	Finalizers              []string          `json:"finalizers,omitempty"`
	GenerateName            string            `json:"generateName,omitempty"`
	Generation              int64             `json:"generation,omitempty"`
	Labels                  map[string]string `json:"labels,omitempty"`
	ManagedFields           []json.RawMessage `json:"managedFields,omitempty"`
	Name                    string            `json:"name"`
	Namespace               string            `json:"namespace"`
	OwnerReferences         []json.RawMessage `json:"ownerReferences,omitempty"`
	ResourceVersion         string            `json:"resourceVersion"`
	UID                     string            `json:"uid"`
}

// GitRepositorySpec is deliberately exact. Credential, provider, verify,
// include, proxy, recursion, suspend, and service-account fields cannot hide in
// this structure because strict decoding rejects them.
type GitRepositorySpec struct {
	Ignore         string       `json:"ignore"`
	Interval       string       `json:"interval"`
	Ref            GitReference `json:"ref"`
	SparseCheckout []string     `json:"sparseCheckout"`
	Timeout        string       `json:"timeout"`
	URL            string       `json:"url"`
}

// GitReference admits only a tag; branch, name, semver, and commit are unknown
// fields and therefore fail strict decoding.
type GitReference struct {
	Tag string `json:"tag"`
}

// GitRepositoryStatus is the source-controller-owned readiness boundary.
type GitRepositoryStatus struct {
	Artifact           *Artifact   `json:"artifact,omitempty"`
	Conditions         []Condition `json:"conditions,omitempty"`
	ObservedGeneration int64       `json:"observedGeneration,omitempty"`
}

// Artifact contains the fields relevant to a tag/commit agreement check.
type Artifact struct {
	Digest   string `json:"digest,omitempty"`
	Path     string `json:"path,omitempty"`
	Revision string `json:"revision"`
	Size     int64  `json:"size,omitempty"`
	URL      string `json:"url,omitempty"`
}

// Condition is the standard Kubernetes condition shape emitted by Flux.
type Condition struct {
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	Message            string `json:"message,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Status             string `json:"status"`
	Type               string `json:"type"`
}

// ValidateCurrent enforces the entire source and returns its admitted tag and
// peeled commit.
func (repository GitRepository) ValidateCurrent() (string, string, error) {
	if repository.APIVersion != "source.toolkit.fluxcd.io/v1" || repository.Kind != "GitRepository" {
		return "", "", fmt.Errorf("root source GVK is foreign")
	}
	metadata := repository.Metadata
	if metadata.Name != GitRepositoryName || metadata.Namespace != GitRepositoryNamespace || metadata.UID == "" || metadata.ResourceVersion == "" || metadata.Generation <= 0 {
		return "", "", fmt.Errorf("root source server identity is incomplete")
	}
	if metadata.DeletionTimestamp != nil || metadata.DeletionGracePeriodSecs != nil || metadata.GenerateName != "" || len(metadata.OwnerReferences) != 0 || len(metadata.Labels) != 0 {
		return "", "", fmt.Errorf("root source metadata is not closed")
	}
	if !validFinalizers(metadata.Finalizers) {
		return "", "", fmt.Errorf("root source finalizers are foreign")
	}
	spec := repository.Spec
	if spec.URL != RepositoryURL || spec.Interval != "1m0s" || spec.Timeout != "60s" || spec.Ignore != ExpectedIgnore || !reflect.DeepEqual(spec.SparseCheckout, []string{"kubernetes/websites/naranjo-online", "kubernetes/websites/lidersea-com"}) {
		return "", "", fmt.Errorf("root source semantic boundary is foreign")
	}
	version, err := ParseVersion(spec.Ref.Tag)
	if err != nil || version.String() != spec.Ref.Tag {
		return "", "", fmt.Errorf("root source tag is invalid")
	}
	target, err := validateCurrentAnnotations(spec.Ref.Tag, metadata.Annotations)
	if err != nil {
		return "", "", err
	}
	return spec.Ref.Tag, target, nil
}

func validFinalizers(finalizers []string) bool {
	return len(finalizers) == 0 || (len(finalizers) == 1 && finalizers[0] == FluxFinalizer)
}

func validateCurrentAnnotations(tag string, annotations map[string]string) (string, error) {
	owned, err := ownedAnnotations(annotations)
	if err != nil {
		return "", err
	}
	if len(owned) != len(evidenceAnnotationKeys) {
		return "", fmt.Errorf("root source evidence annotation set is incomplete or widened")
	}
	for _, key := range evidenceAnnotationKeys {
		if _, present := owned[key]; !present {
			return "", fmt.Errorf("root source evidence annotation set is incomplete")
		}
	}
	if owned[AnnotationSchema] != EvidenceSchema || owned[AnnotationReleaseTag] != tag || !shaRE.MatchString(owned[AnnotationReleaseTargetSHA]) || !shaRE.MatchString(owned[AnnotationTagObjectSHA]) || !runPairRE.MatchString(owned[AnnotationMainCI]) || !runPairRE.MatchString(owned[AnnotationPlatformRelease]) || !ValidDigest(owned[AnnotationSelectorImageDigest]) || !ValidDigest(owned[AnnotationIdentitySHA256]) {
		return "", fmt.Errorf("root source evidence annotations are invalid")
	}
	if _, err := strconvParsePositive(owned[AnnotationReleaseID]); err != nil {
		return "", fmt.Errorf("root source release ID is invalid")
	}
	return owned[AnnotationReleaseTargetSHA], nil
}

func ownedAnnotations(annotations map[string]string) (map[string]string, error) {
	owned := make(map[string]string, len(evidenceAnnotationKeys))
	for key, value := range annotations {
		if !strings.HasPrefix(key, selectorAnnotationPrefix) {
			continue
		}
		known := false
		for _, expected := range evidenceAnnotationKeys {
			if key == expected {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("root source carries a foreign reserved annotation")
		}
		owned[key] = value
	}
	return owned, nil
}

func cloneStringMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func strconvParsePositive(value string) (int64, error) {
	if value == "" || strings.HasPrefix(value, "+") || (len(value) > 1 && value[0] == '0') {
		return 0, fmt.Errorf("non-canonical positive integer")
	}
	maxInt64 := int64(^uint64(0) >> 1)
	var result int64
	for _, character := range value {
		if character < '0' || character > '9' || result > (maxInt64-int64(character-'0'))/10 {
			return 0, fmt.Errorf("non-canonical positive integer")
		}
		result = result*10 + int64(character-'0')
	}
	if result <= 0 {
		return 0, fmt.Errorf("non-canonical positive integer")
	}
	return result, nil
}

// StableWith allows source-controller status/resourceVersion churn and its one
// finalizer lifecycle while refusing every selector-relevant semantic change.
func (repository GitRepository) StableWith(other GitRepository) bool {
	left := repository
	right := other
	left.Status = nil
	right.Status = nil
	left.Metadata.ResourceVersion = ""
	right.Metadata.ResourceVersion = ""
	left.Metadata.ManagedFields = nil
	right.Metadata.ManagedFields = nil
	left.Metadata.Finalizers = nil
	right.Metadata.Finalizers = nil
	return repository.Metadata.UID == other.Metadata.UID && validFinalizers(repository.Metadata.Finalizers) && validFinalizers(other.Metadata.Finalizers) && reflect.DeepEqual(left, right)
}

// WithRelease returns a full-resource conditional PUT payload that changes
// only ref.tag and the nine release-identity annotations.
func (repository GitRepository) WithRelease(snapshot RemoteSnapshot) (GitRepository, error) {
	if snapshot.Absent {
		return GitRepository{}, fmt.Errorf("absent release cannot produce an update")
	}
	updated := repository
	updated.Spec.Ref.Tag = snapshot.Evidence.Release.TagName
	annotations := cloneStringMap(repository.Metadata.Annotations)
	for _, key := range evidenceAnnotationKeys {
		delete(annotations, key)
	}
	for key, value := range EvidenceAnnotations(snapshot.Evidence, snapshot.IdentityDigest) {
		annotations[key] = value
	}
	updated.Metadata.Annotations = annotations
	if updated.Metadata.ResourceVersion == "" || updated.Metadata.UID == "" {
		return GitRepository{}, fmt.Errorf("conditional update lacks UID or resourceVersion")
	}
	return updated, nil
}

// ReadyFor requires current-generation source-controller readiness and the
// pinned Flux v2.9.3 tag revision format.
func (repository GitRepository) ReadyFor(tag, commit string) bool {
	var status GitRepositoryStatus
	if len(repository.Status) == 0 || json.Unmarshal(repository.Status, &status) != nil {
		return false
	}
	if repository.Metadata.Generation <= 0 || status.ObservedGeneration != repository.Metadata.Generation || status.Artifact == nil || status.Artifact.Revision != tag+"@sha1:"+commit {
		return false
	}
	ready := false
	for _, condition := range status.Conditions {
		if condition.Type != "Ready" {
			continue
		}
		if ready || condition.Status != "True" || condition.ObservedGeneration != repository.Metadata.Generation {
			return false
		}
		ready = true
	}
	return ready
}

// InClusterClient is a fixed-path client for the one Flux source object.
type InClusterClient struct {
	client                *http.Client
	sourceEndpoint        string
	kustomizationEndpoint string
	token                 string
}

// NewInClusterClient loads the projected ServiceAccount credential and CA.
func NewInClusterClient() (*InClusterClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = os.Getenv("KUBERNETES_SERVICE_PORT")
	}
	if host == "" || port != "443" || (net.ParseIP(host) == nil && !dnsNameRE.MatchString(host)) {
		return nil, fmt.Errorf("in-cluster Kubernetes endpoint is absent or invalid")
	}
	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("read projected ServiceAccount token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" || len(token) > 16*1024 || strings.ContainsAny(token, " \t\r\n") {
		return nil, fmt.Errorf("projected ServiceAccount token is invalid")
	}
	caBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("Kubernetes CA is invalid")
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	return &InClusterClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("Kubernetes API redirects are forbidden")
			},
		},
		sourceEndpoint:        "https://" + net.JoinHostPort(host, port) + "/apis/source.toolkit.fluxcd.io/v1/namespaces/" + GitRepositoryNamespace + "/gitrepositories/" + GitRepositoryName,
		kustomizationEndpoint: "https://" + net.JoinHostPort(host, port) + "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/" + GitRepositoryNamespace + "/kustomizations/",
		token:                 token,
	}, nil
}

// GetGitRepository reads the one protected source.
func (client *InClusterClient) GetGitRepository(ctx context.Context) (GitRepository, error) {
	payload, err := client.request(ctx, http.MethodGet, client.sourceEndpoint, nil, "")
	if err != nil {
		return GitRepository{}, err
	}
	return decodeGitRepository(payload)
}

// GetKustomization reads one exact direct site reconciler. The selector has no
// Kustomization write method or RBAC verb.
func (client *InClusterClient) GetKustomization(ctx context.Context, name string) (Kustomization, error) {
	if name != NaranjoKustomization && name != LiderseaKustomization {
		return Kustomization{}, fmt.Errorf("site reconciler identity is not allowlisted")
	}
	payload, err := client.request(ctx, http.MethodGet, client.kustomizationEndpoint+name, nil, "")
	if err != nil {
		return Kustomization{}, err
	}
	return decodeKustomization(payload)
}

// PatchGitRepository performs the sole allowed desired-state mutation using
// RFC 6902 compare-and-swap tests. It never calls update, status, finalizer,
// create, delete, or either Kustomization endpoint.
func (client *InClusterClient) PatchGitRepository(ctx context.Context, patch []JSONPatchOperation) (GitRepository, error) {
	payload, err := json.Marshal(patch)
	if err != nil {
		return GitRepository{}, fmt.Errorf("encode conditional GitRepository patch: %w", err)
	}
	response, err := client.request(ctx, http.MethodPatch, client.sourceEndpoint, payload, "application/json-patch+json")
	if err != nil {
		return GitRepository{}, err
	}
	return decodeGitRepository(response)
}

func (client *InClusterClient) request(ctx context.Context, method, endpoint string, payload []byte, contentType string) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("construct Kubernetes request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("User-Agent", "snaraj-platform-release-selector/1")
	if payload != nil {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := client.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("Kubernetes API %s failed: %w", method, err)
	}
	defer response.Body.Close()
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, maxAPIBytes+1))
	if readErr != nil {
		return nil, fmt.Errorf("read Kubernetes API response: %w", readErr)
	}
	if len(responseBytes) > maxAPIBytes {
		return nil, fmt.Errorf("Kubernetes API response exceeds size limit")
	}
	if response.StatusCode == http.StatusConflict {
		return nil, ErrConflict
	}
	if response.StatusCode == http.StatusUnprocessableEntity && genericJSONPatchRejection(responseBytes) {
		return nil, ErrConflict
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Kubernetes API %s returned HTTP %d", method, response.StatusCode)
	}
	return responseBytes, nil
}

func genericJSONPatchRejection(payload []byte) bool {
	var status kubernetesStatus
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil || requireEOF(decoder) != nil {
		return false
	}
	return status.APIVersion == "v1" && status.Kind == "Status" && status.Status == "Failure" &&
		status.Message == genericPatchRejection && status.Reason == "Invalid" && status.Code == http.StatusUnprocessableEntity &&
		bytes.Equal(bytes.TrimSpace(status.Metadata), []byte("{}")) &&
		bytes.Equal(bytes.TrimSpace(status.Details), []byte("{}"))
}

func decodeGitRepository(payload []byte) (GitRepository, error) {
	var repository GitRepository
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&repository); err != nil {
		return repository, fmt.Errorf("decode GitRepository: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return repository, fmt.Errorf("decode GitRepository: %w", err)
	}
	return repository, nil
}
