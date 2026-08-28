package releaseselector

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	IdentityBundleAssetName = "platform-release-identity.v1.json.sigstore.json"
	cosignBinaryPath        = "/usr/local/bin/cosign"
	cosignScratchDirectory  = "/var/run/release-selector"
	cosignTrustedRootPath   = "/usr/local/share/sigstore/trusted_root.json"
	maxBundleBytes          = 1024 * 1024
)

// BundleVerifier proves the detached keyless signature over canonical identity
// bytes. Production uses the digest-pinned cosign binary copied into the image.
type BundleVerifier interface {
	Verify(context.Context, []byte, []byte) error
}

type cosignBundleVerifier struct {
	binary      string
	scratch     string
	trustedRoot string
	timeout     time.Duration
	subject     string
	issuer      string
}

func newCosignBundleVerifier() BundleVerifier {
	return &cosignBundleVerifier{
		binary: cosignBinaryPath, scratch: cosignScratchDirectory,
		trustedRoot: cosignTrustedRootPath, timeout: 20 * time.Second,
		subject: SelectorCertificateSubject, issuer: SelectorCertificateIssuer,
	}
}

func (verifier *cosignBundleVerifier) Verify(ctx context.Context, identity, bundle []byte) error {
	if len(identity) == 0 || len(identity) > maxEvidenceBytes || len(bundle) == 0 || len(bundle) > maxBundleBytes {
		return fmt.Errorf("Sigstore verification input size is invalid")
	}
	if verifier == nil || verifier.binary == "" || verifier.scratch == "" || verifier.trustedRoot == "" || verifier.timeout <= 0 || verifier.subject == "" || verifier.issuer == "" {
		return fmt.Errorf("Sigstore verifier configuration is incomplete")
	}
	info, err := os.Stat(verifier.binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("pinned cosign verifier is unavailable")
	}
	if info, err := os.Stat(verifier.scratch); err != nil || !info.IsDir() {
		return fmt.Errorf("Sigstore scratch directory is unavailable")
	}
	if info, err := os.Stat(verifier.trustedRoot); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("pinned Sigstore trusted root is unavailable")
	}
	identityPath, err := writePrivateTemp(verifier.scratch, "identity-*.json", identity)
	if err != nil {
		return err
	}
	defer os.Remove(identityPath)
	bundlePath, err := writePrivateTemp(verifier.scratch, "bundle-*.json", bundle)
	if err != nil {
		return err
	}
	defer os.Remove(bundlePath)

	verifyContext, cancel := context.WithTimeout(ctx, verifier.timeout)
	defer cancel()
	command := exec.CommandContext(
		verifyContext,
		verifier.binary,
		"verify-blob",
		"--bundle", bundlePath,
		"--trusted-root", verifier.trustedRoot,
		"--certificate-identity", verifier.subject,
		"--certificate-oidc-issuer", verifier.issuer,
		identityPath,
	)
	command.Env = []string{
		"HOME=" + verifier.scratch,
		"TMPDIR=" + verifier.scratch,
		"XDG_CACHE_HOME=" + verifier.scratch,
	}
	// Verification output may contain certificate claims or bundle-derived
	// metadata. Neither stream is logged, buffered, or returned to callers.
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.Stdin = nil
	if err := command.Run(); err != nil {
		if verifyContext.Err() != nil {
			return fmt.Errorf("Sigstore verification deadline: %w", verifyContext.Err())
		}
		return fmt.Errorf("Sigstore bundle verification failed")
	}
	return nil
}

func writePrivateTemp(directory, pattern string, contents []byte) (string, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", fmt.Errorf("create Sigstore verification input: %w", err)
	}
	path := file.Name()
	remove := true
	defer func() {
		if remove {
			os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return "", fmt.Errorf("protect Sigstore verification input: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return "", fmt.Errorf("write Sigstore verification input: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close Sigstore verification input: %w", err)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve Sigstore verification input: %w", err)
	}
	remove = false
	return clean, nil
}
