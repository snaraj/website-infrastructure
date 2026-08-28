package releaseselector

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Kustomization is the closed subset of a direct site reconciler. Strict JSON
// decoding rejects every unreviewed desired-state field.
type Kustomization struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ObjectMeta        `json:"metadata"`
	Spec       KustomizationSpec `json:"spec"`
	Status     json.RawMessage   `json:"status,omitempty"`
}

// KustomizationSpec admits exactly the non-pruning direct-site contract.
type KustomizationSpec struct {
	DeletionPolicy     string          `json:"deletionPolicy"`
	Force              *bool           `json:"force"`
	Interval           string          `json:"interval"`
	Path               string          `json:"path"`
	Prune              bool            `json:"prune"`
	RetryInterval      string          `json:"retryInterval"`
	ServiceAccountName string          `json:"serviceAccountName"`
	SourceRef          SourceReference `json:"sourceRef"`
	Suspend            bool            `json:"suspend"`
	Timeout            string          `json:"timeout"`
	Wait               bool            `json:"wait"`
}

// SourceReference is deliberately namespace-free: cross-namespace source
// references remain disabled and the dedicated source is in flux-system.
type SourceReference struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// KustomizationStatus is the readiness evidence emitted by kustomize-controller.
type KustomizationStatus struct {
	Conditions            []Condition `json:"conditions,omitempty"`
	LastAppliedRevision   string      `json:"lastAppliedRevision,omitempty"`
	LastAttemptedRevision string      `json:"lastAttemptedRevision,omitempty"`
	ObservedGeneration    int64       `json:"observedGeneration,omitempty"`
}

// Validate enforces one of the two exact, active direct-site reconcilers.
func (kustomization Kustomization) Validate(expectedName string) error {
	if expectedName != NaranjoKustomization && expectedName != LiderseaKustomization {
		return fmt.Errorf("site reconciler identity is not allowlisted")
	}
	if kustomization.APIVersion != "kustomize.toolkit.fluxcd.io/v1" || kustomization.Kind != "Kustomization" {
		return fmt.Errorf("site reconciler GVK is foreign")
	}
	metadata := kustomization.Metadata
	if metadata.Name != expectedName || metadata.Namespace != GitRepositoryNamespace || metadata.UID == "" || metadata.ResourceVersion == "" || metadata.Generation <= 0 {
		return fmt.Errorf("site reconciler server identity is incomplete")
	}
	if metadata.DeletionTimestamp != nil || metadata.DeletionGracePeriodSecs != nil || metadata.GenerateName != "" || len(metadata.OwnerReferences) != 0 || !validFinalizers(metadata.Finalizers) {
		return fmt.Errorf("site reconciler metadata is foreign")
	}
	for key := range metadata.Annotations {
		if strings.HasPrefix(key, selectorAnnotationPrefix) {
			return fmt.Errorf("site reconciler carries a foreign reserved annotation")
		}
	}
	site := strings.TrimSuffix(expectedName, "-reconciler")
	if kustomization.Spec.Force == nil || *kustomization.Spec.Force {
		return fmt.Errorf("site reconciler force default is absent or enabled")
	}
	force := false
	wanted := KustomizationSpec{
		DeletionPolicy:     "Orphan",
		Force:              &force,
		Interval:           "10m0s",
		Path:               "./kubernetes/websites/" + site,
		Prune:              false,
		RetryInterval:      "1m0s",
		ServiceAccountName: expectedName,
		SourceRef:          SourceReference{Kind: "GitRepository", Name: GitRepositoryName},
		Suspend:            false,
		Timeout:            "5m0s",
		Wait:               true,
	}
	if !reflect.DeepEqual(kustomization.Spec, wanted) {
		return fmt.Errorf("site reconciler semantic boundary is foreign")
	}
	return nil
}

// ReadyFor requires both applied and attempted revisions plus one unique
// current-generation Ready condition. A predecessor site may keep serving
// while its sibling advances, but the selector never selects another source
// tag until both direct reconcilers prove this revision.
func (kustomization Kustomization) ReadyFor(tag, commit string) bool {
	if kustomization.Validate(kustomization.Metadata.Name) != nil || kustomization.Spec.Suspend {
		return false
	}
	var status KustomizationStatus
	if len(kustomization.Status) == 0 || json.Unmarshal(kustomization.Status, &status) != nil {
		return false
	}
	revision := tag + "@sha1:" + commit
	if status.ObservedGeneration != kustomization.Metadata.Generation || status.LastAppliedRevision != revision || status.LastAttemptedRevision != revision {
		return false
	}
	ready := false
	for _, condition := range status.Conditions {
		if condition.Type != "Ready" {
			continue
		}
		if ready || condition.Status != "True" || condition.ObservedGeneration != kustomization.Metadata.Generation {
			return false
		}
		ready = true
	}
	return ready
}

// SourcePatch returns one guarded JSON Patch. Every mutable precondition is
// tested in the payload: UID, resourceVersion, complete spec, expected tag,
// and every selector-owned annotation. Non-reserved annotations are untouched.
func SourcePatch(repository GitRepository, snapshot RemoteSnapshot) ([]JSONPatchOperation, error) {
	currentTag, _, err := repository.ValidateCurrent()
	if err != nil {
		return nil, err
	}
	if snapshot.Absent || snapshot.Evidence.Release.TagName == currentTag {
		return nil, fmt.Errorf("source patch target is absent or a no-op")
	}
	owned, err := ownedAnnotations(repository.Metadata.Annotations)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(owned))
	for key := range owned {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	patch := []JSONPatchOperation{
		{Operation: "test", Path: "/metadata/uid", Value: repository.Metadata.UID},
		{Operation: "test", Path: "/metadata/resourceVersion", Value: repository.Metadata.ResourceVersion},
		{Operation: "test", Path: "/spec", Value: repository.Spec},
		{Operation: "test", Path: "/spec/ref/tag", Value: currentTag},
	}
	for _, key := range keys {
		patch = append(patch, JSONPatchOperation{Operation: "test", Path: annotationPath(key), Value: owned[key]})
	}
	patch = append(patch, JSONPatchOperation{Operation: "replace", Path: "/spec/ref/tag", Value: snapshot.Evidence.Release.TagName})
	desired := EvidenceAnnotations(snapshot.Evidence, snapshot.IdentityDigest)
	for _, key := range evidenceAnnotationKeys {
		patch = append(patch, JSONPatchOperation{Operation: "replace", Path: annotationPath(key), Value: desired[key]})
	}
	return patch, nil
}

func annotationPath(key string) string {
	return "/metadata/annotations/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

func decodeKustomization(payload []byte) (Kustomization, error) {
	var kustomization Kustomization
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&kustomization); err != nil {
		return kustomization, fmt.Errorf("decode Kustomization: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return kustomization, fmt.Errorf("decode Kustomization: %w", err)
	}
	return kustomization, nil
}
