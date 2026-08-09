// Command server runs the single lidersea.com application artifact. It joins
// the embedded Svelte frontend with the Go HTTP handler and shuts down cleanly
// when Kubernetes replaces or terminates a pod.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/snaraj/website-infrastructure/websites/lidersea.com/internal/server"
	website "github.com/snaraj/website-infrastructure/websites/lidersea.com/internal/web"
)

// main owns process termination, leaving run able to return startup and serving
// failures through one structured log path.
func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// run assembles the immutable site, starts its hardened HTTP server, and blocks
// until the server fails or the operating system requests a graceful shutdown.
func run() error {
	port, err := listenPort(os.Getenv("PORT"))
	if err != nil {
		return err
	}

	assets, err := website.FileSystem()
	if err != nil {
		return err
	}
	handler, err := server.New(assets)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		// Explicit limits protect the Pi-hosted origin from slow or oversized
		// requests while leaving enough time for normal traffic through the tunnel.
		Addr:              ":" + strconv.Itoa(port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Kubernetes sends SIGTERM before a pod's grace period expires; handling both
	// SIGTERM and local interrupts uses the same orderly shutdown path everywhere.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A one-result buffer lets the serving goroutine report an early failure even
	// when signal cancellation wins the select and shutdown begins first.
	errCh := make(chan error, 1)
	go func() {
		slog.Info("lidersea.com listening", "port", port)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case serveErr := <-errCh:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr
	case <-ctx.Done():
	}

	// Bound graceful shutdown so a stuck connection cannot hold a rollout open
	// indefinitely. Kubernetes can still terminate the process after this window.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// listenPort validates the only runtime listener setting. The stable 8080
// default matches the Helm chart, while strict bounds fail bad pod configuration
// before Kubernetes can route traffic to the process.
func listenPort(value string) (int, error) {
	if value == "" {
		return 8080, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("PORT must be an integer between 1 and 65535")
	}
	return port, nil
}
