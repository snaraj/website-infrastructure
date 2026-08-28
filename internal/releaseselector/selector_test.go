package releaseselector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeRemote struct {
	responses []RemoteSnapshot
	calls     []string
}

func (remote *fakeRemote) Snapshot(_ context.Context, currentTag, currentSHA, candidateTag, imageDigest, imageBuildSHA string) (RemoteSnapshot, error) {
	remote.calls = append(remote.calls, currentTag+"/"+currentSHA+"/"+candidateTag+"/"+imageDigest+"/"+imageBuildSHA)
	if len(remote.responses) == 0 {
		return RemoteSnapshot{}, errors.New("unexpected remote read")
	}
	result := remote.responses[0]
	remote.responses = remote.responses[1:]
	return result, nil
}

type fakeCluster struct {
	observations   []clusterObservation
	index          int
	patchErrors    []error
	patchResponses []GitRepository
	patches        [][]JSONPatchOperation
}

func (cluster *fakeCluster) current() (clusterObservation, error) {
	if cluster.index >= len(cluster.observations) {
		return clusterObservation{}, errors.New("unexpected Kubernetes read")
	}
	return cluster.observations[cluster.index], nil
}

func (cluster *fakeCluster) GetGitRepository(context.Context) (GitRepository, error) {
	value, err := cluster.current()
	return value.source, err
}

func (cluster *fakeCluster) GetKustomization(_ context.Context, name string) (Kustomization, error) {
	value, err := cluster.current()
	if err != nil {
		return Kustomization{}, err
	}
	switch name {
	case NaranjoKustomization:
		return value.naranjo, nil
	case LiderseaKustomization:
		cluster.index++
		return value.lidersea, nil
	default:
		return Kustomization{}, errors.New("foreign Kustomization read")
	}
}

func (cluster *fakeCluster) PatchGitRepository(_ context.Context, patch []JSONPatchOperation) (GitRepository, error) {
	cluster.patches = append(cluster.patches, patch)
	if len(cluster.patchErrors) > 0 {
		err := cluster.patchErrors[0]
		cluster.patchErrors = cluster.patchErrors[1:]
		if err != nil {
			return GitRepository{}, err
		}
	}
	if len(cluster.patchResponses) == 0 {
		return GitRepository{}, errors.New("unexpected Kubernetes patch")
	}
	response := cluster.patchResponses[0]
	cluster.patchResponses = cluster.patchResponses[1:]
	return response, nil
}

func currentRepository(resourceVersion string) GitRepository {
	return GitRepository{
		APIVersion: "source.toolkit.fluxcd.io/v1",
		Kind:       "GitRepository",
		Metadata: ObjectMeta{
			Annotations:       cloneStrings(testCurrentAnnotations),
			CreationTimestamp: "2026-08-25T00:00:00Z",
			Generation:        1,
			Name:              GitRepositoryName,
			Namespace:         GitRepositoryNamespace,
			ResourceVersion:   resourceVersion,
			UID:               "uid-fixture-source",
		},
		Spec: GitRepositorySpec{
			Ignore:         ExpectedIgnore,
			Interval:       "1m0s",
			Ref:            GitReference{Tag: testCurrentTag},
			SparseCheckout: []string{"kubernetes/websites/naranjo-online", "kubernetes/websites/lidersea-com"},
			Timeout:        "60s",
			URL:            RepositoryURL,
		},
	}
}

func cloneStrings(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func presentSnapshot(t *testing.T) RemoteSnapshot {
	t.Helper()
	evidence := validEvidence()
	identity := canonicalEvidence(t, evidence)
	parsed, digest, err := ParseIdentity(identity, testCurrentTag, testCurrentSHA, testCandidateTag, testImageDigest, testImageBuildSHA)
	if err != nil {
		t.Fatal(err)
	}
	asset := assetRecord{
		BrowserDownloadURL: "https://github.com/snaraj/website-infrastructure/releases/download/" + testCandidateTag + "/" + IdentityAssetName,
		ContentType:        "application/json",
		Digest:             digest,
		ID:                 400,
		Name:               IdentityAssetName,
		Size:               int64(len(identity)),
		State:              "uploaded",
		URL:                "https://api.github.com/repos/snaraj/website-infrastructure/releases/assets/400",
	}
	bundle := []byte("{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}\n")
	bundleAsset := assetRecord{
		BrowserDownloadURL: "https://github.com/snaraj/website-infrastructure/releases/download/" + testCandidateTag + "/" + IdentityBundleAssetName,
		ContentType:        "application/json",
		Digest:             bytesDigest(bundle),
		ID:                 401,
		Name:               IdentityBundleAssetName,
		Size:               int64(len(bundle)),
		State:              "uploaded",
		URL:                "https://api.github.com/repos/snaraj/website-infrastructure/releases/assets/401",
	}
	return RemoteSnapshot{
		Bundle:         bundle,
		BundleAsset:    bundleAsset,
		Identity:       identity,
		IdentityDigest: digest,
		Asset:          asset,
		Evidence:       parsed,
		MainRun: workflowRun{
			Conclusion: "success", Event: "push", HeadBranch: "main", HeadSHA: parsed.Source.MergeSHA,
			ID: parsed.MainCI.RunID, Path: MainWorkflow, Repository: runRepository{FullName: Repository}, RunAttempt: parsed.MainCI.RunAttempt, Status: "completed",
		},
		PlatformRun: workflowRun{
			Conclusion: "success", Event: "workflow_run", HeadBranch: "main", HeadSHA: parsed.Source.MergeSHA,
			ID: parsed.PlatformRelease.RunID, Path: PlatformWorkflow, Repository: runRepository{FullName: Repository}, RunAttempt: parsed.PlatformRelease.RunAttempt, Status: "completed",
		},
		Release: releaseRecord{
			Assets: []assetRecord{asset, bundleAsset}, Author: releaseAuthor{ID: 41898282, Login: "github-actions[bot]"}, ID: parsed.Release.ID,
			Immutable: true, Name: "Platform " + testCandidateTag, TagName: testCandidateTag, TargetCommitish: parsed.Source.MergeSHA,
		},
		TagRef: tagRefRecord{Object: gitObject{SHA: parsed.Tag.ObjectSHA, Type: "tag"}, Ref: "refs/tags/" + testCandidateTag},
		Tag:    tagRecord{Object: gitObject{SHA: parsed.Source.MergeSHA, Type: "commit"}, SHA: parsed.Tag.ObjectSHA, Tag: testCandidateTag},
	}
}

func sourceReady(repository GitRepository, tag, commit string) GitRepository {
	status, _ := json.Marshal(GitRepositoryStatus{
		Artifact:           &Artifact{Digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Revision: tag + "@sha1:" + commit},
		Conditions:         []Condition{{ObservedGeneration: repository.Metadata.Generation, Status: "True", Type: "Ready"}},
		ObservedGeneration: repository.Metadata.Generation,
	})
	repository.Status = status
	return repository
}

func siteKustomization(name, tag, commit string, ready bool) Kustomization {
	site := name[:len(name)-len("-reconciler")]
	force := false
	result := Kustomization{
		APIVersion: "kustomize.toolkit.fluxcd.io/v1",
		Kind:       "Kustomization",
		Metadata: ObjectMeta{
			CreationTimestamp: "2026-08-25T00:00:00Z",
			Generation:        1,
			Name:              name,
			Namespace:         GitRepositoryNamespace,
			ResourceVersion:   "20",
			UID:               name + "-uid",
		},
		Spec: KustomizationSpec{
			DeletionPolicy: "Orphan", Force: &force, Interval: "10m0s", Path: "./kubernetes/websites/" + site,
			RetryInterval: "1m0s", ServiceAccountName: name, SourceRef: SourceReference{Kind: "GitRepository", Name: GitRepositoryName},
			Timeout: "5m0s", Wait: true,
		},
	}
	if ready {
		status, _ := json.Marshal(KustomizationStatus{
			Conditions:          []Condition{{ObservedGeneration: 1, Status: "True", Type: "Ready"}},
			LastAppliedRevision: tag + "@sha1:" + commit, LastAttemptedRevision: tag + "@sha1:" + commit, ObservedGeneration: 1,
		})
		result.Status = status
	}
	return result
}

func observation(source GitRepository, tag, commit string, naranjoReady, liderseaReady bool) clusterObservation {
	return clusterObservation{
		source:   source,
		naranjo:  siteKustomization(NaranjoKustomization, tag, commit, naranjoReady),
		lidersea: siteKustomization(LiderseaKustomization, tag, commit, liderseaReady),
		tag:      tag,
		commit:   commit,
	}
}

func targetRepository(base GitRepository, snapshot RemoteSnapshot, ready bool) GitRepository {
	result, _ := base.WithRelease(snapshot)
	result.Metadata.Generation = 2
	result.Metadata.ResourceVersion = "30"
	if ready {
		result = sourceReady(result, snapshot.Evidence.Release.TagName, snapshot.Evidence.Source.MergeSHA)
	}
	return result
}

func withAnnotation(repository GitRepository, key, value string) GitRepository {
	repository.Metadata.Annotations = cloneStrings(repository.Metadata.Annotations)
	repository.Metadata.Annotations[key] = value
	return repository
}

func replaceSiteUID(observation clusterObservation, name string) clusterObservation {
	switch name {
	case NaranjoKustomization:
		observation.naranjo.Metadata.UID = "replacement-naranjo-uid"
	case LiderseaKustomization:
		observation.lidersea.Metadata.UID = "replacement-lidersea-uid"
	}
	return observation
}

func TestSelectorCommitsSourceOnceAndAllowsPartialSiteConvergence(t *testing.T) {
	snapshot := presentSnapshot(t)
	predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	target := targetRepository(predecessor, snapshot, true)
	cluster := &fakeCluster{
		observations: []clusterObservation{
			observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
			observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
			observation(target, testCandidateTag, snapshot.Evidence.Source.MergeSHA, true, false),
			observation(target, testCandidateTag, snapshot.Evidence.Source.MergeSHA, true, true),
		},
		patchResponses: []GitRepository{targetRepository(predecessor, snapshot, false)},
	}
	selector := New(&fakeRemote{responses: []RemoteSnapshot{snapshot, snapshot}}, cluster, testImageDigest, testImageBuildSHA)
	selector.poll = 0
	selector.casBackoff = 0
	outcome, err := selector.Run(context.Background())
	if err != nil || outcome != OutcomeUpdated {
		t.Fatalf("unexpected result %q: %v", outcome, err)
	}
	if len(cluster.patches) != 1 {
		t.Fatalf("wanted one source patch, got %d", len(cluster.patches))
	}
	assertGuardedPatch(t, cluster.patches[0], "10")
}

func TestSelectorBoundsPersistentStaleCASRetries(t *testing.T) {
	snapshot := presentSnapshot(t)
	first := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	observations := []clusterObservation{
		observation(first, testCurrentTag, testCurrentSHA, true, true),
		observation(first, testCurrentTag, testCurrentSHA, true, true),
	}
	for _, resourceVersion := range []string{"11", "12", "13"} {
		fresh := sourceReady(currentRepository(resourceVersion), testCurrentTag, testCurrentSHA)
		fresh.Status = first.Status
		observations = append(observations, observation(fresh, testCurrentTag, testCurrentSHA, true, true))
	}
	cluster := &fakeCluster{
		observations: observations,
		patchErrors:  []error{ErrConflict, ErrConflict, ErrConflict},
	}
	selector := New(&fakeRemote{responses: []RemoteSnapshot{snapshot, snapshot}}, cluster, testImageDigest, testImageBuildSHA)
	selector.casRetries = 2
	selector.casBackoff = 0
	if _, err := selector.Run(context.Background()); err == nil || len(cluster.patches) != 3 {
		t.Fatalf("persistent stale CAS was not bounded: patches=%d err=%v", len(cluster.patches), err)
	}
	assertGuardedPatch(t, cluster.patches[0], "10")
	assertGuardedPatch(t, cluster.patches[1], "11")
	assertGuardedPatch(t, cluster.patches[2], "12")
}

func TestSelectorTreatsForeignPatchErrorsAsTerminal(t *testing.T) {
	snapshot := presentSnapshot(t)
	predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	cluster := &fakeCluster{
		observations: []clusterObservation{
			observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
			observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
		},
		patchErrors: []error{errors.New("foreign Kubernetes error")},
	}
	selector := New(&fakeRemote{responses: []RemoteSnapshot{snapshot, snapshot}}, cluster, testImageDigest, testImageBuildSHA)
	if _, err := selector.Run(context.Background()); err == nil {
		t.Fatal("foreign patch failure was retried or accepted")
	}
	if len(cluster.patches) != 1 || cluster.index != 2 {
		t.Fatalf("foreign error crossed the terminal boundary: patches=%d observations=%d", len(cluster.patches), cluster.index)
	}
}

func TestSelectorRecoversForwardWithoutAWriteAfterCrashAtCommitPoint(t *testing.T) {
	snapshot := presentSnapshot(t)
	predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	target := targetRepository(predecessor, snapshot, true)
	cluster := &fakeCluster{observations: []clusterObservation{
		observation(target, testCandidateTag, snapshot.Evidence.Source.MergeSHA, true, false),
		observation(target, testCandidateTag, snapshot.Evidence.Source.MergeSHA, true, true),
	}}
	remote := &fakeRemote{}
	selector := New(remote, cluster, testImageDigest, testImageBuildSHA)
	selector.poll = 0
	outcome, err := selector.Run(context.Background())
	if err != nil || outcome != OutcomeConverged || len(cluster.patches) != 0 || len(remote.calls) != 0 {
		t.Fatalf("unexpected recovery %q patches=%d remote=%d err=%v", outcome, len(cluster.patches), len(remote.calls), err)
	}
}

func TestSelectorOn409DiscardsPatchAndRebuildsFromFreshRead(t *testing.T) {
	snapshot := presentSnapshot(t)
	first := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	second := sourceReady(currentRepository("11"), testCurrentTag, testCurrentSHA)
	second.Status = first.Status
	target := targetRepository(second, snapshot, true)
	cluster := &fakeCluster{
		observations: []clusterObservation{
			observation(first, testCurrentTag, testCurrentSHA, true, true),
			observation(first, testCurrentTag, testCurrentSHA, true, true),
			observation(second, testCurrentTag, testCurrentSHA, true, true),
			observation(target, testCandidateTag, snapshot.Evidence.Source.MergeSHA, true, true),
		},
		patchErrors:    []error{ErrConflict, nil},
		patchResponses: []GitRepository{targetRepository(second, snapshot, false)},
	}
	selector := New(&fakeRemote{responses: []RemoteSnapshot{snapshot, snapshot}}, cluster, testImageDigest, testImageBuildSHA)
	selector.poll = 0
	selector.casBackoff = 0
	if outcome, err := selector.Run(context.Background()); err != nil || outcome != OutcomeUpdated {
		t.Fatalf("unexpected result %q: %v", outcome, err)
	}
	if len(cluster.patches) != 2 {
		t.Fatalf("wanted fresh rebuilt patch, got %d", len(cluster.patches))
	}
	assertGuardedPatch(t, cluster.patches[0], "10")
	assertGuardedPatch(t, cluster.patches[1], "11")
}

func TestSelectorRejectsForeignConflictAndNeverRollsBack(t *testing.T) {
	snapshot := presentSnapshot(t)
	predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	foreign := predecessor
	foreign.Metadata.UID = "foreign-uid"
	cluster := &fakeCluster{
		observations: []clusterObservation{
			observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
			observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
			observation(foreign, testCurrentTag, testCurrentSHA, true, true),
		},
		patchErrors: []error{ErrConflict},
	}
	selector := New(&fakeRemote{responses: []RemoteSnapshot{snapshot, snapshot}}, cluster, testImageDigest, testImageBuildSHA)
	selector.poll = 0
	if _, err := selector.Run(context.Background()); err == nil {
		t.Fatal("foreign conflict was accepted")
	}
	if len(cluster.patches) != 1 {
		t.Fatalf("foreign state triggered another write: %d", len(cluster.patches))
	}
}

func TestSelectorRejectsSiteReplacementDuringCASInference(t *testing.T) {
	t.Parallel()
	for _, site := range []string{NaranjoKustomization, LiderseaKustomization} {
		site := site
		t.Run(site, func(t *testing.T) {
			t.Parallel()
			snapshot := presentSnapshot(t)
			predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
			stable := observation(predecessor, testCurrentTag, testCurrentSHA, true, true)
			cluster := &fakeCluster{
				observations: []clusterObservation{stable, stable, replaceSiteUID(stable, site)},
				patchErrors:  []error{ErrConflict},
			}
			selector := New(&fakeRemote{responses: []RemoteSnapshot{snapshot, snapshot}}, cluster, testImageDigest, testImageBuildSHA)
			selector.casBackoff = 0
			if _, err := selector.Run(context.Background()); err == nil {
				t.Fatal("site replacement during CAS inference was accepted")
			}
			if len(cluster.patches) != 1 {
				t.Fatalf("site replacement triggered a stale retry: %d", len(cluster.patches))
			}
		})
	}
}

func TestSelectorNoopsOnlyAfterTwoMatchingAbsentReads(t *testing.T) {
	absent := RemoteSnapshot{Absent: true}
	predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	cluster := &fakeCluster{observations: []clusterObservation{
		observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
		observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
	}}
	remote := &fakeRemote{responses: []RemoteSnapshot{absent, absent}}
	outcome, err := New(remote, cluster, testImageDigest, testImageBuildSHA).Run(context.Background())
	if err != nil || outcome != OutcomeNoCandidate || len(cluster.patches) != 0 || len(remote.calls) != 2 {
		t.Fatalf("unexpected no-candidate result %q, patches=%d calls=%d err=%v", outcome, len(cluster.patches), len(remote.calls), err)
	}
	wantCall := testCurrentTag + "/" + testCurrentSHA + "/" + testCandidateTag + "/" + testImageDigest + "/" + testImageBuildSHA
	for _, call := range remote.calls {
		if call != wantCall {
			t.Fatalf("selector did not propagate the exact image/build tuple: got %q want %q", call, wantCall)
		}
	}
}

func TestSelectorRejectsMissingOrInvalidBuildSourceBeforeRemoteRead(t *testing.T) {
	predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	for _, buildSHA := range []string{"", strings.Repeat("f", 39), strings.ToUpper(strings.Repeat("ab", 20))} {
		cluster := &fakeCluster{observations: []clusterObservation{
			observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
		}}
		remote := &fakeRemote{}
		if _, err := New(remote, cluster, testImageDigest, buildSHA).Run(context.Background()); err == nil {
			t.Fatalf("invalid selector build source %q was accepted", buildSHA)
		}
		if len(remote.calls) != 0 || cluster.index != 0 {
			t.Fatal("invalid selector build source crossed the preflight boundary")
		}
	}
}

func TestSelectorRejectsSuspendedOrForeignSiteBeforeRemoteReads(t *testing.T) {
	predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	value := observation(predecessor, testCurrentTag, testCurrentSHA, true, true)
	value.naranjo.Spec.Suspend = true
	cluster := &fakeCluster{observations: []clusterObservation{value}}
	remote := &fakeRemote{}
	if _, err := New(remote, cluster, testImageDigest, testImageBuildSHA).Run(context.Background()); err == nil {
		t.Fatal("suspended site reconciler was accepted")
	}
	if len(remote.calls) != 0 || len(cluster.patches) != 0 {
		t.Fatal("selector crossed a foreign site boundary")
	}
}

func TestSelectorRejectsForeignSiteSemantics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Kustomization)
	}{
		{name: "missing-service-account", mutate: func(value *Kustomization) { value.Spec.ServiceAccountName = "" }},
		{name: "prune-enabled", mutate: func(value *Kustomization) { value.Spec.Prune = true }},
		{name: "missing-force-default", mutate: func(value *Kustomization) { value.Spec.Force = nil }},
		{name: "force-enabled", mutate: func(value *Kustomization) { enabled := true; value.Spec.Force = &enabled }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := siteKustomization(NaranjoKustomization, testCurrentTag, testCurrentSHA, true)
			test.mutate(&value)
			if err := value.Validate(NaranjoKustomization); err == nil {
				t.Fatal("foreign site reconciler contract was accepted")
			}
		})
	}
}

func TestDecodeKustomizationAcceptsOnlyPresentDisabledForceDefault(t *testing.T) {
	canonical, err := json.Marshal(siteKustomization(NaranjoKustomization, testCurrentTag, testCurrentSHA, true))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonical, []byte(`"force":false`)) {
		t.Fatal("serialized API response omitted defaulted force:false")
	}
	decoded, err := decodeKustomization(canonical)
	if err != nil || decoded.Spec.Force == nil || *decoded.Spec.Force {
		t.Fatalf("API-defaulted force:false was not decoded: %#v %v", decoded.Spec.Force, err)
	}
	for name, payload := range map[string][]byte{
		"missing": bytes.Replace(canonical, []byte(`"force":false,`), nil, 1),
		"enabled": bytes.Replace(canonical, []byte(`"force":false`), []byte(`"force":true`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			value, err := decodeKustomization(payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := value.Validate(NaranjoKustomization); err == nil {
				t.Fatal("foreign force state was accepted")
			}
		})
	}
}

func TestSelectorPinsBothSiteUIDsBeforeCommit(t *testing.T) {
	t.Parallel()
	for _, site := range []string{NaranjoKustomization, LiderseaKustomization} {
		site := site
		t.Run(site, func(t *testing.T) {
			t.Parallel()
			snapshot := presentSnapshot(t)
			predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
			first := observation(predecessor, testCurrentTag, testCurrentSHA, true, true)
			second := replaceSiteUID(first, site)
			cluster := &fakeCluster{observations: []clusterObservation{first, second}}
			remote := &fakeRemote{responses: []RemoteSnapshot{snapshot}}
			if _, err := New(remote, cluster, testImageDigest, testImageBuildSHA).Run(context.Background()); err == nil {
				t.Fatal("site replacement before commit was accepted")
			}
			if len(cluster.patches) != 0 || len(remote.calls) != 1 {
				t.Fatalf("site replacement crossed commit boundary: patches=%d remote=%d", len(cluster.patches), len(remote.calls))
			}
		})
	}
}

func TestSelectorPinsBothSiteUIDsThroughoutConvergence(t *testing.T) {
	t.Parallel()
	for _, site := range []string{NaranjoKustomization, LiderseaKustomization} {
		site := site
		t.Run(site, func(t *testing.T) {
			t.Parallel()
			snapshot := presentSnapshot(t)
			predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
			target := targetRepository(predecessor, snapshot, true)
			cluster := &fakeCluster{
				observations: []clusterObservation{
					observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
					observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
					replaceSiteUID(observation(target, testCandidateTag, snapshot.Evidence.Source.MergeSHA, true, true), site),
				},
				patchResponses: []GitRepository{targetRepository(predecessor, snapshot, false)},
			}
			selector := New(&fakeRemote{responses: []RemoteSnapshot{snapshot, snapshot}}, cluster, testImageDigest, testImageBuildSHA)
			selector.poll = 0
			if _, err := selector.Run(context.Background()); err == nil {
				t.Fatal("site replacement during convergence was accepted")
			}
			if len(cluster.patches) != 1 {
				t.Fatalf("replacement caused a second write: %d", len(cluster.patches))
			}
		})
	}
}

func TestSelectorRejectsValidLookingEvidenceSubstitutionDuringRecovery(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "main-run", key: AnnotationMainCI, value: "999999/1"},
		{name: "identity-digest", key: AnnotationIdentitySHA256, value: "sha256:" + strings.Repeat("e", 64)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := presentSnapshot(t)
			predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
			target := targetRepository(predecessor, snapshot, true)
			drifted := withAnnotation(target, test.key, test.value)
			cluster := &fakeCluster{observations: []clusterObservation{
				observation(target, testCandidateTag, snapshot.Evidence.Source.MergeSHA, true, false),
				observation(drifted, testCandidateTag, snapshot.Evidence.Source.MergeSHA, true, true),
			}}
			selector := New(&fakeRemote{}, cluster, testImageDigest, testImageBuildSHA)
			selector.poll = 0
			if _, err := selector.Run(context.Background()); err == nil {
				t.Fatal("valid-looking recovery evidence substitution was accepted")
			}
			if len(cluster.patches) != 0 {
				t.Fatal("recovery evidence substitution caused a write")
			}
		})
	}
}

func TestSelectorRejectsValidLookingEvidenceSubstitutionAfterCommit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "platform-run", key: AnnotationPlatformRelease, value: "888888/2"},
		{name: "selector-digest", key: AnnotationSelectorImageDigest, value: "sha256:" + strings.Repeat("f", 64)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := presentSnapshot(t)
			predecessor := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
			target := targetRepository(predecessor, snapshot, true)
			drifted := withAnnotation(target, test.key, test.value)
			cluster := &fakeCluster{
				observations: []clusterObservation{
					observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
					observation(predecessor, testCurrentTag, testCurrentSHA, true, true),
					observation(drifted, testCandidateTag, snapshot.Evidence.Source.MergeSHA, true, true),
				},
				patchResponses: []GitRepository{targetRepository(predecessor, snapshot, false)},
			}
			selector := New(&fakeRemote{responses: []RemoteSnapshot{snapshot, snapshot}}, cluster, testImageDigest, testImageBuildSHA)
			selector.poll = 0
			if _, err := selector.Run(context.Background()); err == nil {
				t.Fatal("valid-looking post-commit evidence substitution was accepted")
			}
			if len(cluster.patches) != 1 {
				t.Fatalf("post-commit evidence substitution caused another write: %d", len(cluster.patches))
			}
		})
	}
}

func TestReadyForRejectsDuplicateOrStaleReadyConditions(t *testing.T) {
	repository := sourceReady(currentRepository("10"), testCurrentTag, testCurrentSHA)
	var status GitRepositoryStatus
	if err := json.Unmarshal(repository.Status, &status); err != nil {
		t.Fatal(err)
	}
	status.Conditions = append(status.Conditions, status.Conditions[0])
	repository.Status, _ = json.Marshal(status)
	if repository.ReadyFor(testCurrentTag, testCurrentSHA) {
		t.Fatal("duplicate Ready conditions were accepted")
	}
	status.Conditions = status.Conditions[:1]
	status.Conditions[0].ObservedGeneration--
	repository.Status, _ = json.Marshal(status)
	if repository.ReadyFor(testCurrentTag, testCurrentSHA) {
		t.Fatal("stale Ready condition was accepted")
	}
}

func assertGuardedPatch(t *testing.T, patch []JSONPatchOperation, resourceVersion string) {
	t.Helper()
	wantedTests := map[string]any{
		"/metadata/uid":             "uid-fixture-source",
		"/metadata/resourceVersion": resourceVersion,
		"/spec/ref/tag":             testCurrentTag,
	}
	for _, operation := range patch {
		if operation.Operation == "test" {
			delete(wantedTests, operation.Path)
		}
	}
	if len(wantedTests) != 0 {
		t.Fatalf("patch omitted CAS tests: %#v", wantedTests)
	}
	completeSpec := false
	annotationTests := 0
	for _, operation := range patch {
		if operation.Operation == "test" && operation.Path == "/spec" {
			completeSpec = true
		}
		if operation.Operation == "test" && len(operation.Path) > len("/metadata/annotations/") && operation.Path[:len("/metadata/annotations/")] == "/metadata/annotations/" {
			annotationTests++
		}
	}
	if !completeSpec || annotationTests != len(evidenceAnnotationKeys) {
		t.Fatalf("patch did not test complete spec and owned annotations: spec=%t annotations=%d", completeSpec, annotationTests)
	}
	if !reflect.DeepEqual(patch[len(patch)-len(evidenceAnnotationKeys)-1], JSONPatchOperation{Operation: "replace", Path: "/spec/ref/tag", Value: testCandidateTag}) {
		t.Fatal("patch did not perform the one source commit point")
	}
}
