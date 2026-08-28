// Package releaseselector implements the fail-closed platform release selector.
package releaseselector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	Repository                 = "snaraj/website-infrastructure"
	RepositoryURL              = "https://github.com/snaraj/website-infrastructure.git"
	IdentityAssetName          = "platform-release-identity.v1.json"
	EvidenceSchema             = "https://snaraj.dev/schemas/platform-release-identity/v1"
	ProtectedRef               = "refs/heads/main"
	MainWorkflow               = ".github/workflows/pull-request.yml"
	PlatformWorkflow           = ".github/workflows/platform-release.yml"
	SelectorImage              = "ghcr.io/snaraj/website-infrastructure/platform-release-selector"
	SelectorCertificateIssuer  = "https://token.actions.githubusercontent.com"
	SelectorCertificateSubject = "https://github.com/snaraj/website-infrastructure/.github/workflows/platform-release.yml@refs/heads/main"
	ProvenancePredicateType    = "https://slsa.dev/provenance/v1"
	maxEvidenceBytes           = 64 * 1024
)

var (
	shaRE          = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestRE       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	fragmentRE     = regexp.MustCompile(`^changelog\.d/[1-9][0-9]*-[a-z0-9]+(?:-[a-z0-9]+)*\.md$`)
	chartVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	versionRE      = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
)

// Evidence is the complete canonical GitHub Release identity asset. Its nested field
// order is irrelevant because canonical bytes are checked independently.
type Evidence struct {
	Changelog       ChangelogEvidence `json:"changelog"`
	MainCI          RunEvidence       `json:"main_ci"`
	PlatformRelease RunEvidence       `json:"platform_release"`
	Predecessor     Predecessor       `json:"predecessor"`
	Release         ReleaseEvidence   `json:"release"`
	Repository      string            `json:"repository"`
	Schema          string            `json:"schema"`
	Selector        SelectorEvidence  `json:"selector"`
	Sites           SitesEvidence     `json:"sites"`
	Source          SourceEvidence    `json:"source"`
	Tag             TagEvidence       `json:"tag"`
}

// SitesEvidence binds both chart artifacts and the workload identities they
// embed. The fixed struct rejects missing, duplicate, renamed, or extra sites.
type SitesEvidence struct {
	LiderseaCom   SiteEvidence `json:"lidersea-com"`
	NaranjoOnline SiteEvidence `json:"naranjo-online"`
}

// SiteEvidence is the immutable public identity tuple for one website release.
type SiteEvidence struct {
	Chart    ChartEvidence    `json:"chart"`
	Workload WorkloadEvidence `json:"workload"`
}

// ChartEvidence identifies the exact signed Helm artifact and extracted layer.
type ChartEvidence struct {
	LayerDigest    string `json:"layer_digest"`
	ManifestDigest string `json:"manifest_digest"`
	Repository     string `json:"repository"`
	Version        string `json:"version"`
}

// WorkloadEvidence identifies the signed multi-platform image embedded by the
// chart and its independently verified ARM64 child.
type WorkloadEvidence struct {
	Arm64Digest string `json:"arm64_digest"`
	Image       string `json:"image"`
}

// ChangelogEvidence binds the one release fragment without embedding mutable
// generated release notes.
type ChangelogEvidence struct {
	FragmentPath   string `json:"fragment_path"`
	FragmentSHA256 string `json:"fragment_sha256"`
}

// RunEvidence selects one workflow attempt deterministically. Conclusion is
// present only for the completed main-CI run; the platform workflow cannot
// truthfully attest its own final conclusion before publishing the Release.
type RunEvidence struct {
	Conclusion string `json:"conclusion,omitempty"`
	Event      string `json:"event"`
	HeadSHA    string `json:"head_sha"`
	Ref        string `json:"ref"`
	RunAttempt int64  `json:"run_attempt"`
	RunID      int64  `json:"run_id"`
	Workflow   string `json:"workflow"`
}

// Predecessor prevents an arbitrary higher tag from entering the selection
// window.
type Predecessor struct {
	PeeledCommit string `json:"peeled_commit"`
	Tag          string `json:"tag"`
}

// ReleaseEvidence mirrors the immutable REST record that carries exactly the
// canonical identity and detached Sigstore bundle assets.
type ReleaseEvidence struct {
	AssetCount      int64  `json:"asset_count"`
	Draft           bool   `json:"draft"`
	ID              int64  `json:"id"`
	Immutable       bool   `json:"immutable"`
	Prerelease      bool   `json:"prerelease"`
	TagName         string `json:"tag_name"`
	TargetCommitish string `json:"target_commitish"`
}

// SelectorEvidence binds the executing image and its keyless trust tuple.
type SelectorEvidence struct {
	Digest     string             `json:"digest"`
	Image      string             `json:"image"`
	Provenance ProvenanceEvidence `json:"provenance"`
	Signature  SignatureEvidence  `json:"signature"`
}

// SignatureEvidence is the exact keyless certificate policy used at bootstrap.
type SignatureEvidence struct {
	CertificateIdentity string `json:"certificate_identity"`
	OIDCIssuer          string `json:"oidc_issuer"`
}

// ProvenanceEvidence binds the SLSA predicate to the same immutable subject.
type ProvenanceEvidence struct {
	AttestorIdentity string `json:"attestor_identity"`
	PredicateType    string `json:"predicate_type"`
	SourceSHA        string `json:"source_sha"`
	SubjectDigest    string `json:"subject_digest"`
}

// SourceEvidence is the protected-main merge selected by both workflows.
type SourceEvidence struct {
	MergeSHA     string `json:"merge_sha"`
	ProtectedRef string `json:"protected_ref"`
	TreeSHA      string `json:"tree_sha"`
}

// TagEvidence binds the annotated object and the commit it peels to.
type TagEvidence struct {
	Name         string `json:"name"`
	ObjectSHA    string `json:"object_sha"`
	ObjectType   string `json:"object_type"`
	PeeledCommit string `json:"peeled_commit"`
}

// Version is a canonical vMAJOR.MINOR.PATCH tag.
type Version struct {
	Major uint64
	Minor uint64
	Patch uint64
}

// ParseVersion rejects leading zeroes, suffixes, and non-patch release names.
func ParseVersion(value string) (Version, error) {
	match := versionRE.FindStringSubmatch(value)
	if match == nil {
		return Version{}, fmt.Errorf("tag is not canonical vMAJOR.MINOR.PATCH")
	}
	parts := make([]uint64, 3)
	for index := range parts {
		parsed, err := strconv.ParseUint(match[index+1], 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("tag component is outside uint64")
		}
		parts[index] = parsed
	}
	return Version{Major: parts[0], Minor: parts[1], Patch: parts[2]}, nil
}

// String returns the canonical tag form.
func (version Version) String() string {
	return fmt.Sprintf("v%d.%d.%d", version.Major, version.Minor, version.Patch)
}

// NextPatch returns exactly one patch after the current version.
func (version Version) NextPatch() (Version, error) {
	if version.Patch == ^uint64(0) {
		return Version{}, fmt.Errorf("patch version overflows uint64")
	}
	version.Patch++
	return version, nil
}

// ValidDigest reports whether a string is one canonical SHA-256 digest.
func ValidDigest(value string) bool {
	return digestRE.MatchString(value)
}

// ValidSourceSHA reports whether a string is one canonical Git object SHA-1.
// The selector build identity is passed separately from the platform release
// source because a reviewed selector image may be reused by later releases.
func ValidSourceSHA(value string) bool {
	return shaRE.MatchString(value)
}

// ParseIdentity accepts only the exact canonical asset bytes and the expected
// current-to-candidate edge.
func ParseIdentity(body []byte, currentTag, currentSHA, candidateTag, expectedImageDigest, expectedImageBuildSHA string) (Evidence, string, error) {
	var evidence Evidence
	if len(body) == 0 || len(body) > maxEvidenceBytes || !utf8.Valid(body) {
		return evidence, "", fmt.Errorf("release identity size or UTF-8 is invalid")
	}
	if bytes.Contains(body, []byte{'\r'}) || body[len(body)-1] != '\n' || bytes.HasSuffix(body, []byte("\n\n")) {
		return evidence, "", fmt.Errorf("release identity must have one terminal LF")
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return evidence, "", fmt.Errorf("release identity schema: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return evidence, "", err
	}
	typedCanonical, err := json.Marshal(evidence)
	if err != nil {
		return evidence, "", fmt.Errorf("canonical typed release identity: %w", err)
	}
	typedCanonical = append(typedCanonical, '\n')
	if !bytes.Equal(body, typedCanonical) {
		return evidence, "", fmt.Errorf("release identity does not exactly match the typed canonical schema")
	}

	var generic any
	genericDecoder := json.NewDecoder(bytes.NewReader(body))
	genericDecoder.UseNumber()
	if err := genericDecoder.Decode(&generic); err != nil {
		return evidence, "", fmt.Errorf("release identity JSON: %w", err)
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		return evidence, "", fmt.Errorf("canonical release identity: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(body, canonical) {
		return evidence, "", fmt.Errorf("release identity is not canonical sorted compact JSON")
	}

	if err := evidence.validate(currentTag, currentSHA, candidateTag, expectedImageDigest, expectedImageBuildSHA); err != nil {
		return evidence, "", err
	}
	digest := sha256.Sum256(body)
	return evidence, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("release identity carries trailing JSON")
		}
		return fmt.Errorf("release identity trailing bytes: %w", err)
	}
	return nil
}

func (e Evidence) validate(currentTag, currentSHA, candidateTag, expectedImageDigest, expectedImageBuildSHA string) error {
	if e.Schema != EvidenceSchema || e.Repository != Repository {
		return fmt.Errorf("release identity schema or repository is foreign")
	}
	if !shaRE.MatchString(currentSHA) || e.Predecessor.Tag != currentTag || e.Predecessor.PeeledCommit != currentSHA {
		return fmt.Errorf("release predecessor does not equal the admitted source")
	}
	if e.Source.ProtectedRef != ProtectedRef || !shaRE.MatchString(e.Source.MergeSHA) || !shaRE.MatchString(e.Source.TreeSHA) || e.Source.TreeSHA == e.Source.MergeSHA || e.Source.MergeSHA == currentSHA {
		return fmt.Errorf("protected source identity is invalid")
	}
	if e.Tag.Name != candidateTag || e.Tag.ObjectType != "tag" || !shaRE.MatchString(e.Tag.ObjectSHA) || e.Tag.PeeledCommit != e.Source.MergeSHA {
		return fmt.Errorf("annotated tag evidence is invalid")
	}
	if e.Release.ID <= 0 || e.Release.TagName != candidateTag || e.Release.TargetCommitish != e.Source.MergeSHA || !e.Release.Immutable || e.Release.Draft || e.Release.Prerelease || e.Release.AssetCount != 2 {
		return fmt.Errorf("GitHub Release identity is not immutable, published, and exactly two-asset")
	}
	if err := validateRun(e.MainCI, MainWorkflow, "push", true, e.Source.MergeSHA); err != nil {
		return fmt.Errorf("main CI evidence: %w", err)
	}
	if err := validateRun(e.PlatformRelease, PlatformWorkflow, "workflow_run", false, e.Source.MergeSHA); err != nil {
		return fmt.Errorf("platform release evidence: %w", err)
	}
	if e.Selector.Image != SelectorImage || e.Selector.Digest != expectedImageDigest || !ValidDigest(e.Selector.Digest) || !ValidSourceSHA(expectedImageBuildSHA) {
		return fmt.Errorf("selector image evidence does not match the executing image")
	}
	if e.Selector.Signature.CertificateIdentity != SelectorCertificateSubject || e.Selector.Signature.OIDCIssuer != SelectorCertificateIssuer {
		return fmt.Errorf("selector signature identity is foreign")
	}
	if e.Selector.Provenance.AttestorIdentity != SelectorCertificateSubject || e.Selector.Provenance.PredicateType != ProvenancePredicateType || e.Selector.Provenance.SourceSHA != expectedImageBuildSHA || e.Selector.Provenance.SubjectDigest != e.Selector.Digest {
		return fmt.Errorf("selector provenance identity is foreign")
	}
	if !fragmentRE.MatchString(e.Changelog.FragmentPath) || !ValidDigest(e.Changelog.FragmentSHA256) {
		return fmt.Errorf("changelog evidence is invalid")
	}
	if err := e.Sites.validate(); err != nil {
		return err
	}
	return nil
}

func (sites SitesEvidence) validate() error {
	for slug, site := range map[string]SiteEvidence{
		"lidersea-com":   sites.LiderseaCom,
		"naranjo-online": sites.NaranjoOnline,
	} {
		expectedRepository := "ghcr.io/snaraj/charts/" + slug
		if site.Chart.Repository != expectedRepository || !chartVersionRE.MatchString(site.Chart.Version) || !ValidDigest(site.Chart.ManifestDigest) || !ValidDigest(site.Chart.LayerDigest) || site.Chart.ManifestDigest == site.Chart.LayerDigest {
			return fmt.Errorf("%s chart identity is invalid", slug)
		}
		prefix := "ghcr.io/snaraj/" + slug + ":v" + site.Chart.Version + "@"
		if !strings.HasPrefix(site.Workload.Image, prefix) || !ValidDigest(strings.TrimPrefix(site.Workload.Image, prefix)) || !ValidDigest(site.Workload.Arm64Digest) || strings.HasSuffix(site.Workload.Image, site.Workload.Arm64Digest) {
			return fmt.Errorf("%s workload identity is invalid", slug)
		}
	}
	return nil
}

func validateRun(run RunEvidence, workflow, event string, requireConclusion bool, sourceSHA string) error {
	if run.RunID <= 0 || run.RunAttempt <= 0 || run.Workflow != workflow || run.Event != event || run.Ref != ProtectedRef || run.HeadSHA != sourceSHA {
		return fmt.Errorf("workflow attempt identity is invalid")
	}
	if requireConclusion && run.Conclusion != "success" {
		return fmt.Errorf("required successful conclusion is absent")
	}
	if !requireConclusion && run.Conclusion != "" {
		return fmt.Errorf("self-referential platform conclusion must be absent")
	}
	return nil
}

// EvidenceAnnotations returns the only metadata the selector may change.
func EvidenceAnnotations(e Evidence, identityDigest string) map[string]string {
	return map[string]string{
		AnnotationSchema:              EvidenceSchema,
		AnnotationReleaseID:           strconv.FormatInt(e.Release.ID, 10),
		AnnotationReleaseTag:          e.Release.TagName,
		AnnotationReleaseTargetSHA:    e.Release.TargetCommitish,
		AnnotationTagObjectSHA:        e.Tag.ObjectSHA,
		AnnotationMainCI:              fmt.Sprintf("%d/%d", e.MainCI.RunID, e.MainCI.RunAttempt),
		AnnotationPlatformRelease:     fmt.Sprintf("%d/%d", e.PlatformRelease.RunID, e.PlatformRelease.RunAttempt),
		AnnotationSelectorImageDigest: e.Selector.Digest,
		AnnotationIdentitySHA256:      identityDigest,
	}
}

// SafeTag is suitable for bounded error messages and never returns untrusted
// control characters.
func SafeTag(value string) string {
	if versionRE.MatchString(value) {
		return value
	}
	return "<invalid-tag>"
}

// canonicalRunKey is used only for equality diagnostics without serializing a
// complete untrusted API response.
func canonicalRunKey(run RunEvidence) string {
	return strings.Join([]string{strconv.FormatInt(run.RunID, 10), strconv.FormatInt(run.RunAttempt, 10), run.Workflow}, "/")
}
