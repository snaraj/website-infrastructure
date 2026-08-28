// Command platform-release-selector advances the bootstrap-owned Flux source
// to the exact next immutable platform release.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/snaraj/website-infrastructure/internal/releaseselector"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "platform release selector: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	digest := os.Getenv("EXPECTED_SELECTOR_IMAGE_DIGEST")
	if !releaseselector.ValidDigest(digest) {
		return fmt.Errorf("EXPECTED_SELECTOR_IMAGE_DIGEST is absent or invalid")
	}
	buildSHA := os.Getenv("EXPECTED_SELECTOR_BUILD_SHA")
	if !releaseselector.ValidSourceSHA(buildSHA) {
		return fmt.Errorf("EXPECTED_SELECTOR_BUILD_SHA is absent or invalid")
	}

	github, err := releaseselector.NewGitHubClient()
	if err != nil {
		return err
	}
	kubernetes, err := releaseselector.NewInClusterClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	outcome, err := releaseselector.New(github, kubernetes, digest, buildSHA).Run(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("platform release selector: %s\n", outcome)
	return nil
}
