package releaseselector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeVerifierScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cosign")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTrustedRoot(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCosignBundleVerifierUsesExactIdentityAndIssuerAndCleansInputs(t *testing.T) {
	script := writeVerifierScript(t,
		`[ "$1" = verify-blob ] && [ "$2" = --bundle ] && [ "$4" = --trusted-root ] && `+
			`[ -s "$5" ] && [ "$6" = --certificate-identity ] && `+
			`[ "$7" = '`+SelectorCertificateSubject+`' ] && [ "$8" = --certificate-oidc-issuer ] && `+
			`[ "$9" = '`+SelectorCertificateIssuer+`' ] && [ -s "$3" ] && [ -s "${10}" ] && `+
			`[ "$HOME" = "$TMPDIR" ] && [ "$HOME" = "$XDG_CACHE_HOME" ]`,
	)
	scratch := t.TempDir()
	verifier := &cosignBundleVerifier{
		binary: script, scratch: scratch, trustedRoot: writeTrustedRoot(t), timeout: time.Second,
		subject: SelectorCertificateSubject, issuer: SelectorCertificateIssuer,
	}
	if err := verifier.Verify(context.Background(), []byte("identity\n"), []byte("bundle\n")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("verification inputs were not removed: %#v", entries)
	}
}

func TestCosignBundleVerifierFailsClosed(t *testing.T) {
	validScript := writeVerifierScript(t,
		`[ "$7" = '`+SelectorCertificateSubject+`' ] && [ "$9" = '`+SelectorCertificateIssuer+`' ]`,
	)
	trustedRoot := writeTrustedRoot(t)
	cases := map[string]*cosignBundleVerifier{
		"missing binary": {
			binary: filepath.Join(t.TempDir(), "missing"), scratch: t.TempDir(), trustedRoot: trustedRoot, timeout: time.Second,
			subject: SelectorCertificateSubject, issuer: SelectorCertificateIssuer,
		},
		"missing trusted root": {
			binary: validScript, scratch: t.TempDir(), trustedRoot: filepath.Join(t.TempDir(), "missing"), timeout: time.Second,
			subject: SelectorCertificateSubject, issuer: SelectorCertificateIssuer,
		},
		"failed verification": {
			binary: writeVerifierScript(t, "exit 1"), scratch: t.TempDir(), trustedRoot: trustedRoot, timeout: time.Second,
			subject: SelectorCertificateSubject, issuer: SelectorCertificateIssuer,
		},
		"wrong subject": {
			binary: validScript, scratch: t.TempDir(), trustedRoot: trustedRoot, timeout: time.Second,
			subject: "https://github.com/snaraj/foreign/.github/workflows/platform-release.yml@refs/heads/main", issuer: SelectorCertificateIssuer,
		},
		"wrong issuer": {
			binary: validScript, scratch: t.TempDir(), trustedRoot: trustedRoot, timeout: time.Second,
			subject: SelectorCertificateSubject, issuer: "https://example.invalid",
		},
		"timeout": {
			binary: writeVerifierScript(t, "while :; do :; done"), scratch: t.TempDir(), trustedRoot: trustedRoot, timeout: 10 * time.Millisecond,
			subject: SelectorCertificateSubject, issuer: SelectorCertificateIssuer,
		},
	}
	for name, verifier := range cases {
		t.Run(name, func(t *testing.T) {
			if err := verifier.Verify(context.Background(), []byte("identity\n"), []byte("bundle\n")); err == nil {
				t.Fatal("hostile verifier state was accepted")
			}
		})
	}
}
