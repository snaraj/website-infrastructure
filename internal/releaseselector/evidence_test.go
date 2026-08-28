package releaseselector

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testImageDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testImageBuildSHA = "6666666666666666666666666666666666666666"
	testCurrentTag    = "v0.1.40"
	testCandidateTag  = "v0.1.41"
	testCurrentSHA    = "3333333333333333333333333333333333333333"
)

var testCurrentAnnotations = map[string]string{
	AnnotationSchema:              EvidenceSchema,
	AnnotationReleaseID:           "299",
	AnnotationReleaseTag:          testCurrentTag,
	AnnotationReleaseTargetSHA:    testCurrentSHA,
	AnnotationTagObjectSHA:        "4444444444444444444444444444444444444444",
	AnnotationMainCI:              "98/1",
	AnnotationPlatformRelease:     "99/1",
	AnnotationSelectorImageDigest: testImageDigest,
	AnnotationIdentitySHA256:      "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
}

func validEvidence() Evidence {
	return Evidence{
		Changelog: ChangelogEvidence{
			FragmentPath:   "changelog.d/189-platform-release-selector.md",
			FragmentSHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		MainCI: RunEvidence{
			Conclusion: "success",
			Event:      "push",
			HeadSHA:    "1111111111111111111111111111111111111111",
			Ref:        ProtectedRef,
			RunAttempt: 2,
			RunID:      100,
			Workflow:   MainWorkflow,
		},
		PlatformRelease: RunEvidence{
			Event:      "workflow_run",
			HeadSHA:    "1111111111111111111111111111111111111111",
			Ref:        ProtectedRef,
			RunAttempt: 3,
			RunID:      200,
			Workflow:   PlatformWorkflow,
		},
		Predecessor: Predecessor{PeeledCommit: testCurrentSHA, Tag: testCurrentTag},
		Release: ReleaseEvidence{
			AssetCount:      2,
			Draft:           false,
			ID:              300,
			Immutable:       true,
			Prerelease:      false,
			TagName:         testCandidateTag,
			TargetCommitish: "1111111111111111111111111111111111111111",
		},
		Repository: Repository,
		Schema:     EvidenceSchema,
		Selector: SelectorEvidence{
			Digest: testImageDigest,
			Image:  SelectorImage,
			Provenance: ProvenanceEvidence{
				AttestorIdentity: SelectorCertificateSubject,
				PredicateType:    ProvenancePredicateType,
				SourceSHA:        testImageBuildSHA,
				SubjectDigest:    testImageDigest,
			},
			Signature: SignatureEvidence{
				CertificateIdentity: SelectorCertificateSubject,
				OIDCIssuer:          SelectorCertificateIssuer,
			},
		},
		Sites: SitesEvidence{
			LiderseaCom: SiteEvidence{
				Chart: ChartEvidence{
					LayerDigest:    "sha256:1190b1297885d233a01f362467a00eb8f32c49ca5843edeb8af53d5a25f21b3b",
					ManifestDigest: "sha256:05ab03a6e7520ea6768e4efc3750c83f8f7bc827cac3289bf9ee1326c873c8fc",
					Repository:     "ghcr.io/snaraj/charts/lidersea-com",
					Version:        "0.1.37",
				},
				Workload: WorkloadEvidence{
					Arm64Digest: "sha256:4dbe9d8ca117a8b7023646cb9197b9de4208d03283ba172b386d8598d8d2e233",
					Image:       "ghcr.io/snaraj/lidersea-com:v0.1.37@sha256:22673a01a892da2b644369ee3c2d0339c13ef8eddc1d3423411ce90bbe25d8b1",
				},
			},
			NaranjoOnline: SiteEvidence{
				Chart: ChartEvidence{
					LayerDigest:    "sha256:4d1215d746c601d8ad1ed97a4a6d8b7785489dc4c39f3d5f264ebeeead053dd1",
					ManifestDigest: "sha256:22a29d488a9578d87d4a2f69fd02e4ef35daa1fb5800bc6bd12ac974b73a8c42",
					Repository:     "ghcr.io/snaraj/charts/naranjo-online",
					Version:        "0.1.50",
				},
				Workload: WorkloadEvidence{
					Arm64Digest: "sha256:ce24ca15fce26bc46361c23d5691620967dc39aaf13ba99d0dfe17053ebf2392",
					Image:       "ghcr.io/snaraj/naranjo-online:v0.1.50@sha256:89a9e34730d32ee68338da93c8d146b315441e454aae55a70db349396295b41f",
				},
			},
		},
		Source: SourceEvidence{
			MergeSHA:     "1111111111111111111111111111111111111111",
			ProtectedRef: ProtectedRef,
			TreeSHA:      "5555555555555555555555555555555555555555",
		},
		Tag: TagEvidence{
			Name:         testCandidateTag,
			ObjectSHA:    "2222222222222222222222222222222222222222",
			ObjectType:   "tag",
			PeeledCommit: "1111111111111111111111111111111111111111",
		},
	}
}

func canonicalEvidence(t *testing.T, evidence Evidence) []byte {
	t.Helper()
	payload, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	return append(payload, '\n')
}

func TestParseEvidenceAcceptsCanonicalExactNextIdentityAsset(t *testing.T) {
	identity := canonicalEvidence(t, validEvidence())
	evidence, digest, err := ParseIdentity(identity, testCurrentTag, testCurrentSHA, testCandidateTag, testImageDigest, testImageBuildSHA)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Release.ID != 300 || !ValidDigest(digest) {
		t.Fatalf("unexpected parsed evidence: %#v %q", evidence.Release, digest)
	}
}

func TestParseEvidenceBindsReusedSelectorToItsBuildSource(t *testing.T) {
	value := validEvidence()
	if value.Source.MergeSHA == testImageBuildSHA {
		t.Fatal("fixture does not model a successor platform release reusing the selector image")
	}
	payload := canonicalEvidence(t, value)
	if _, _, err := ParseIdentity(payload, testCurrentTag, testCurrentSHA, testCandidateTag, testImageDigest, testImageBuildSHA); err != nil {
		t.Fatalf("successor release rejected the carried selector build identity: %v", err)
	}
	if _, _, err := ParseIdentity(payload, testCurrentTag, testCurrentSHA, testCandidateTag, testImageDigest, value.Source.MergeSHA); err == nil {
		t.Fatal("successor platform source was accepted as the reused selector build source")
	}
	if _, _, err := ParseIdentity(payload, testCurrentTag, testCurrentSHA, testCandidateTag, testImageDigest, "7777777777777777777777777777777777777777"); err == nil {
		t.Fatal("wrong selector build source was accepted")
	}
}

func TestParseEvidenceRejectsNonCanonicalAndConflictingBodies(t *testing.T) {
	base := validEvidence()
	for name, mutate := range map[string]func([]byte, *Evidence) []byte{
		"pretty JSON": func(_ []byte, value *Evidence) []byte {
			payload, _ := json.MarshalIndent(value, "", "  ")
			return append(payload, '\n')
		},
		"unknown field": func(payload []byte, _ *Evidence) []byte {
			return bytes.Replace(payload, []byte(`{"changelog":`), []byte(`{"aaa":true,"changelog":`), 1)
		},
		"duplicate field": func(payload []byte, _ *Evidence) []byte {
			return bytes.Replace(payload, []byte(`{"changelog":`), []byte(`{"repository":"snaraj/website-infrastructure","changelog":`), 1)
		},
		"case variant Draft": func(payload []byte, _ *Evidence) []byte {
			var document map[string]any
			decoder := json.NewDecoder(bytes.NewReader(payload))
			decoder.UseNumber()
			if err := decoder.Decode(&document); err != nil {
				t.Fatal(err)
			}
			release, ok := document["release"].(map[string]any)
			if !ok {
				t.Fatal("release fixture is not an object")
			}
			release["Draft"] = release["draft"]
			delete(release, "draft")
			canonical, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			return append(canonical, '\n')
		},
		"draft null": func(payload []byte, _ *Evidence) []byte {
			return bytes.Replace(payload, []byte(`"draft":false`), []byte(`"draft":null`), 1)
		},
		"omitted false draft": func(payload []byte, _ *Evidence) []byte {
			return bytes.Replace(payload, []byte(`"draft":false,`), nil, 1)
		},
		"CRLF": func(payload []byte, _ *Evidence) []byte {
			return bytes.ReplaceAll(payload, []byte("\n"), []byte("\r\n"))
		},
		"moved target": func(_ []byte, value *Evidence) []byte {
			value.Tag.PeeledCommit = "3333333333333333333333333333333333333333"
			return canonicalEvidence(t, *value)
		},
		"invalid source tree": func(_ []byte, value *Evidence) []byte {
			value.Source.TreeSHA = value.Source.MergeSHA
			return canonicalEvidence(t, *value)
		},
		"predecessor commit reused": func(_ []byte, value *Evidence) []byte {
			value.Source.MergeSHA = testCurrentSHA
			value.Tag.PeeledCommit = testCurrentSHA
			value.Release.TargetCommitish = testCurrentSHA
			value.MainCI.HeadSHA = testCurrentSHA
			value.PlatformRelease.HeadSHA = testCurrentSHA
			return canonicalEvidence(t, *value)
		},
		"mutable release": func(_ []byte, value *Evidence) []byte {
			value.Release.Immutable = false
			return canonicalEvidence(t, *value)
		},
		"wrong asset count": func(_ []byte, value *Evidence) []byte {
			value.Release.AssetCount = 0
			return canonicalEvidence(t, *value)
		},
		"noncanonical changelog issue": func(_ []byte, value *Evidence) []byte {
			value.Changelog.FragmentPath = "changelog.d/0-foreign.md"
			return canonicalEvidence(t, *value)
		},
		"foreign site digest": func(_ []byte, value *Evidence) []byte {
			value.Sites.NaranjoOnline.Chart.ManifestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			value.Sites.NaranjoOnline.Chart.LayerDigest = value.Sites.NaranjoOnline.Chart.ManifestDigest
			return canonicalEvidence(t, *value)
		},
		"wrong selector": func(_ []byte, value *Evidence) []byte {
			value.Selector.Digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			value.Selector.Provenance.SubjectDigest = value.Selector.Digest
			return canonicalEvidence(t, *value)
		},
		"self success claim": func(_ []byte, value *Evidence) []byte {
			value.PlatformRelease.Conclusion = "success"
			return canonicalEvidence(t, *value)
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			payload := mutate(canonicalEvidence(t, value), &value)
			if _, _, err := ParseIdentity(payload, testCurrentTag, testCurrentSHA, testCandidateTag, testImageDigest, testImageBuildSHA); err == nil {
				t.Fatal("hostile release identity was accepted")
			}
		})
	}
}

func TestVersionOnlyAdvancesOnePatch(t *testing.T) {
	version, err := ParseVersion("v12.34.56")
	if err != nil {
		t.Fatal(err)
	}
	next, err := version.NextPatch()
	if err != nil || next.String() != "v12.34.57" {
		t.Fatalf("unexpected next patch: %v %v", next, err)
	}
	for _, invalid := range []string{"0.1.25", "v0.01.25", "v0.1.40-rc.1", "v0.1", "v0.1.40\n"} {
		if _, err := ParseVersion(invalid); err == nil {
			t.Fatalf("accepted invalid version %q", strings.TrimSpace(invalid))
		}
	}
}
