// Command authorize-svc is the decision-plane HTTP service (skeleton).
//
// Scaffold scope only (ROADMAP Task 0.1): boot, connect to Postgres + Redis,
// serve /health, shut down gracefully. No authorization business logic yet.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trust-infra/authorize-svc/internal/auth"
	"github.com/trust-infra/authorize-svc/internal/config"
	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/logging"
	"github.com/trust-infra/authorize-svc/internal/ratelimit"
	"github.com/trust-infra/authorize-svc/internal/server"
	"github.com/trust-infra/authorize-svc/internal/store"
)

// Build info, injected at build time via -ldflags (see Makefile).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	build := server.BuildInfo{Version: version, Commit: commit, Date: date}

	log.Info("starting", "service", "authorize-svc",
		"version", build.Version, "commit", build.Commit, "addr", cfg.Addr)

	// Connect to backing stores. Fail fast if either is unreachable at boot.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pg, err := store.NewPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("postgres connect failed", "err", err)
		os.Exit(1)
	}
	defer pg.Close()
	log.Info("connected", "store", "postgres")

	rds, err := store.NewRedis(ctx, cfg.RedisURL)
	if err != nil {
		log.Error("redis connect failed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = rds.Close() }()
	log.Info("connected", "store", "redis")

	// Phase-0 authorizer seam: hardcoded APPROVE. The real engine implements the
	// same interface next; swapping it is a one-line change here.
	authz := engine.Stub{
		PolicyVersionHash: cfg.PolicyVersionHash,
		SigningKeyID:      cfg.SigningKeyID,
	}

	// Request authentication (TRD §11): key records from Postgres (source of truth)
	// fronted by a short-TTL Redis cache; per-key nonces in Redis for replay
	// protection.
	keyStore := auth.NewCachedKeyStore(
		auth.NewRedisKeyCache(rds.Client),
		auth.NewPostgresKeyStore(pg.Pool),
		cfg.KeyCacheTTL,
	)
	authn := auth.New(keyStore, auth.NewRedisNonceStore(rds.Client), auth.Config{
		MaxSkew:  cfg.HMACMaxSkew,
		NonceTTL: cfg.NonceTTL,
	})

	// Per-key rate limiting (TRD §11, Task 1.3): shared Redis counters so limits
	// hold across instances. Tier limits come from the key's tier.
	limiter := ratelimit.NewRedisLimiter(rds.Client)
	tiers := ratelimit.DefaultTiers()

	srv := server.New(log, build, authz, authn, limiter, tiers,
		server.Check{Name: "postgres", Ping: pg.Ping},
		server.Check{Name: "redis", Ping: rds.Ping},
	)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Serve until an interrupt, then drain in-flight requests.
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Error("http server error", "err", err)
		os.Exit(1)
	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	log.Info("stopped")
}
