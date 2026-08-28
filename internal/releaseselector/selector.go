package releaseselector

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"
)

// Outcome is intentionally small enough for a liveness probe and log parser.
type Outcome string

const (
	// OutcomeNoCandidate means both exact-next remote observations were absent.
	OutcomeNoCandidate Outcome = "NO_CANDIDATE"
	// OutcomeConverged means a prior source commit point recovered forward and
	// both independent reconcilers reached its exact revision.
	OutcomeConverged Outcome = "CONVERGED"
	// OutcomeUpdated means this run committed the source tag and both independent
	// reconcilers subsequently reached its exact revision.
	OutcomeUpdated Outcome = "UPDATED"
)

// Selector has one desired-state write: a guarded JSON Patch on the dedicated
// GitRepository. The two site Kustomizations are read-only proof boundaries.
type Selector struct {
	remote        RemoteReader
	cluster       ClusterReaderWriter
	imageDigest   string
	imageBuildSHA string
	poll          time.Duration
	casRetries    int
	casBackoff    time.Duration
}

// New constructs a selector with no credential or mutation surface beyond the
// two injected interfaces.
func New(remote RemoteReader, cluster ClusterReaderWriter, imageDigest, imageBuildSHA string) *Selector {
	return &Selector{
		remote:        remote,
		cluster:       cluster,
		imageDigest:   imageDigest,
		imageBuildSHA: imageBuildSHA,
		poll:          5 * time.Second,
		casRetries:    3,
		casBackoff:    250 * time.Millisecond,
	}
}

type clusterObservation struct {
	source   GitRepository
	naranjo  Kustomization
	lidersea Kustomization
	tag      string
	commit   string
}

// convergencePins bind the three bootstrap-owned object identities and the
// exact signed source evidence. Resource versions and controller status may
// advance, but object replacement or a valid-looking evidence substitution is
// never convergence.
type convergencePins struct {
	sourceUID   string
	naranjoUID  string
	liderseaUID string
	annotations map[string]string
}

// Run first proves the currently selected revision converged everywhere. Only
// then may it validate and commit the exact next immutable release. The source
// patch is the forward-only commit point: a crash, timeout, or partial site
// reconciliation never rolls it back, and a later run waits at that tag before
// considering another candidate.
func (selector *Selector) Run(ctx context.Context) (Outcome, error) {
	if selector.remote == nil || selector.cluster == nil || !ValidDigest(selector.imageDigest) || !ValidSourceSHA(selector.imageBuildSHA) {
		return "", fmt.Errorf("selector configuration is incomplete")
	}

	observed, err := selector.observe(ctx)
	if err != nil {
		return "", err
	}
	pins, err := observed.pins()
	if err != nil {
		return "", err
	}
	if !observed.ready() {
		if _, err := selector.waitFor(ctx, observed.tag, observed.commit, pins); err != nil {
			return "", fmt.Errorf("forward convergence at %s: %w", SafeTag(observed.tag), err)
		}
		return OutcomeConverged, nil
	}

	currentVersion, err := ParseVersion(observed.tag)
	if err != nil {
		return "", err
	}
	nextVersion, err := currentVersion.NextPatch()
	if err != nil {
		return "", err
	}
	candidateTag := nextVersion.String()
	firstRemote, err := selector.remote.Snapshot(ctx, observed.tag, observed.commit, candidateTag, selector.imageDigest, selector.imageBuildSHA)
	if err != nil {
		return "", fmt.Errorf("first remote read: %w", err)
	}

	second, err := selector.observe(ctx)
	if err != nil {
		return "", fmt.Errorf("pre-commit observation: %w", err)
	}
	if err := pins.validate(second); err != nil || !sameSource(observed.source, second.source) || second.tag != observed.tag || second.commit != observed.commit || !second.ready() {
		return "", fmt.Errorf("protected source or site readiness changed before second remote read")
	}
	secondRemote, err := selector.remote.Snapshot(ctx, observed.tag, observed.commit, candidateTag, selector.imageDigest, selector.imageBuildSHA)
	if err != nil {
		return "", fmt.Errorf("second remote read: %w", err)
	}
	if !firstRemote.Equal(secondRemote) {
		return "", fmt.Errorf("candidate %s changed between remote reads", SafeTag(candidateTag))
	}
	if secondRemote.Absent {
		return OutcomeNoCandidate, nil
	}

	predecessor := second.source
	targetPins := pins
	targetPins.annotations = cloneStringMap(pins.annotations)
	for _, key := range evidenceAnnotationKeys {
		delete(targetPins.annotations, key)
	}
	for key, value := range EvidenceAnnotations(secondRemote.Evidence, secondRemote.IdentityDigest) {
		targetPins.annotations[key] = value
	}
	staleRetries := 0
	for {
		patch, err := SourcePatch(second.source, secondRemote)
		if err != nil {
			return "", err
		}
		response, err := selector.cluster.PatchGitRepository(ctx, patch)
		if err == nil {
			if err := validatePatchResponse(second.source, response, secondRemote); err != nil {
				return "", err
			}
			break
		}
		if !errors.Is(err, ErrConflict) {
			return "", fmt.Errorf("source patch failed before the commit point: %w", err)
		}
		fresh, readErr := selector.observe(ctx)
		if readErr != nil {
			return "", fmt.Errorf("fresh observation after source patch failure: %w", readErr)
		}
		if !pins.sameObjectUIDs(fresh) {
			return "", fmt.Errorf("source conflict replaced a protected object")
		}
		if sourceIsTarget(fresh.source, secondRemote, predecessor.Metadata.UID) {
			if err := targetPins.validate(fresh); err != nil {
				return "", fmt.Errorf("source conflict reached a foreign target: %w", err)
			}
			break
		}
		if fresh.tag != observed.tag || fresh.commit != observed.commit || !sameSource(predecessor, fresh.source) {
			return "", fmt.Errorf("source conflict resolved to a foreign or moved state")
		}
		if !fresh.ready() {
			return "", fmt.Errorf("source conflict invalidated predecessor readiness")
		}
		if staleRetries >= selector.casRetries {
			return "", fmt.Errorf("source compare-and-swap retry limit exhausted")
		}
		staleRetries++
		if err := selector.waitCASBackoff(ctx); err != nil {
			return "", err
		}
		// The 409/closed-422 payload is discarded. Rebuild every test from this
		// fresh GET; a stale patch body is never replayed.
		second = fresh
	}

	if _, err := selector.waitFor(ctx, candidateTag, secondRemote.Evidence.Source.MergeSHA, targetPins); err != nil {
		return "", fmt.Errorf("forward convergence at %s: %w", SafeTag(candidateTag), err)
	}
	return OutcomeUpdated, nil
}

func (selector *Selector) observe(ctx context.Context) (clusterObservation, error) {
	var result clusterObservation
	source, err := selector.cluster.GetGitRepository(ctx)
	if err != nil {
		return result, fmt.Errorf("GitRepository read: %w", err)
	}
	tag, commit, err := source.ValidateCurrent()
	if err != nil {
		return result, fmt.Errorf("GitRepository read: %w", err)
	}
	naranjo, err := selector.cluster.GetKustomization(ctx, NaranjoKustomization)
	if err != nil {
		return result, fmt.Errorf("naranjo reconciler read: %w", err)
	}
	if err := naranjo.Validate(NaranjoKustomization); err != nil {
		return result, fmt.Errorf("naranjo reconciler read: %w", err)
	}
	lidersea, err := selector.cluster.GetKustomization(ctx, LiderseaKustomization)
	if err != nil {
		return result, fmt.Errorf("lidersea reconciler read: %w", err)
	}
	if err := lidersea.Validate(LiderseaKustomization); err != nil {
		return result, fmt.Errorf("lidersea reconciler read: %w", err)
	}
	return clusterObservation{source: source, naranjo: naranjo, lidersea: lidersea, tag: tag, commit: commit}, nil
}

func (observation clusterObservation) ready() bool {
	return observation.source.ReadyFor(observation.tag, observation.commit) &&
		observation.naranjo.ReadyFor(observation.tag, observation.commit) &&
		observation.lidersea.ReadyFor(observation.tag, observation.commit)
}

func (observation clusterObservation) pins() (convergencePins, error) {
	if _, err := ownedAnnotations(observation.source.Metadata.Annotations); err != nil {
		return convergencePins{}, err
	}
	return convergencePins{
		sourceUID:   observation.source.Metadata.UID,
		naranjoUID:  observation.naranjo.Metadata.UID,
		liderseaUID: observation.lidersea.Metadata.UID,
		annotations: cloneStringMap(observation.source.Metadata.Annotations),
	}, nil
}

func (pins convergencePins) sameObjectUIDs(observation clusterObservation) bool {
	return observation.source.Metadata.UID == pins.sourceUID &&
		observation.naranjo.Metadata.UID == pins.naranjoUID &&
		observation.lidersea.Metadata.UID == pins.liderseaUID
}

func (pins convergencePins) validate(observation clusterObservation) error {
	if !pins.sameObjectUIDs(observation) {
		return fmt.Errorf("protected source or site reconciler was replaced")
	}
	if _, err := ownedAnnotations(observation.source.Metadata.Annotations); err != nil || !reflect.DeepEqual(observation.source.Metadata.Annotations, pins.annotations) {
		return fmt.Errorf("protected source evidence changed during convergence")
	}
	return nil
}

func (selector *Selector) waitFor(ctx context.Context, tag, commit string, pins convergencePins) (clusterObservation, error) {
	for {
		observed, err := selector.observe(ctx)
		if err != nil {
			return clusterObservation{}, err
		}
		if err := pins.validate(observed); err != nil || observed.tag != tag || observed.commit != commit {
			return clusterObservation{}, fmt.Errorf("protected source moved or was replaced during convergence")
		}
		if observed.ready() {
			return observed, nil
		}
		timer := time.NewTimer(selector.poll)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return clusterObservation{}, fmt.Errorf("readiness deadline: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func (selector *Selector) waitCASBackoff(ctx context.Context) error {
	if selector.casBackoff <= 0 {
		return nil
	}
	timer := time.NewTimer(selector.casBackoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("source compare-and-swap backoff: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

func sameSource(left, right GitRepository) bool {
	return left.StableWith(right)
}

func sourceIsTarget(source GitRepository, snapshot RemoteSnapshot, uid string) bool {
	tag, commit, err := source.ValidateCurrent()
	if err != nil || source.Metadata.UID != uid || tag != snapshot.Evidence.Release.TagName || commit != snapshot.Evidence.Source.MergeSHA {
		return false
	}
	owned, err := ownedAnnotations(source.Metadata.Annotations)
	return err == nil && reflect.DeepEqual(owned, EvidenceAnnotations(snapshot.Evidence, snapshot.IdentityDigest))
}

func validatePatchResponse(before, response GitRepository, snapshot RemoteSnapshot) error {
	if !sourceIsTarget(response, snapshot, before.Metadata.UID) {
		return fmt.Errorf("source patch response identity is foreign")
	}
	expected, err := before.WithRelease(snapshot)
	if err != nil {
		return err
	}
	expected.Metadata.Generation = response.Metadata.Generation
	expected.Metadata.ResourceVersion = response.Metadata.ResourceVersion
	expected.Metadata.ManagedFields = response.Metadata.ManagedFields
	expected.Metadata.Finalizers = response.Metadata.Finalizers
	expected.Status = response.Status
	if !reflect.DeepEqual(expected, response) {
		return fmt.Errorf("source patch response changed a field outside tag and reserved annotations")
	}
	return nil
}
