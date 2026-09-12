// Command authorize-svc is the decision-plane HTTP service (skeleton).
//
// Scaffold scope only (ROADMAP Task 0.1): boot, connect to Postgres + Redis,
// serve /health, shut down gracefully. No authorization business logic yet.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trust-infra/authorize-svc/internal/audit"
	"github.com/trust-infra/authorize-svc/internal/auth"
	"github.com/trust-infra/authorize-svc/internal/bundle"
	"github.com/trust-infra/authorize-svc/internal/config"
	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/idempotency"
	"github.com/trust-infra/authorize-svc/internal/logging"
	"github.com/trust-infra/authorize-svc/internal/policy"
	"github.com/trust-infra/authorize-svc/internal/policyctl"
	"github.com/trust-infra/authorize-svc/internal/ratelimit"
	"github.com/trust-infra/authorize-svc/internal/server"
	"github.com/trust-infra/authorize-svc/internal/signing"
	"github.com/trust-infra/authorize-svc/internal/store"
)

// decodeSeed decodes a 32-byte Ed25519 seed from base64 (std or url) or hex.
func decodeSeed(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("AUTHZ_SIGNING_PRIVATE_KEY must be a 32-byte Ed25519 seed in base64 or hex")
}

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

	// Decision signing (Task 1.5): load the Ed25519 signing key, or generate a dev key
	// at boot. The public half is published at /v1/keys/public so any third party can
	// verify decisions. Production supplies the seed from the secret manager.
	keyring := signing.NewKeyring()
	if cfg.SigningPrivateKey != "" {
		seed, derr := decodeSeed(cfg.SigningPrivateKey)
		if derr != nil {
			log.Error("signing key decode failed", "err", derr)
			os.Exit(1)
		}
		if err := keyring.SetActive(cfg.SigningKeyID, seed); err != nil {
			log.Error("signing key load failed", "err", err)
			os.Exit(1)
		}
		log.Info("signing key loaded", "key_id", cfg.SigningKeyID)
	} else {
		id, err := keyring.GenerateActive()
		if err != nil {
			log.Error("signing key generate failed", "err", err)
			os.Exit(1)
		}
		log.Warn("generated an ephemeral signing key (dev only; decisions won't verify across restarts)", "key_id", id)
	}
	signer, err := keyring.Signer()
	if err != nil {
		log.Error("signer unavailable", "err", err)
		os.Exit(1)
	}

	// Decision engine (Task 1.4/1.7): the real deterministic engine, evaluating a
	// policy loaded from a JSON file (AUTHZ_POLICY_FILE) or the embedded default
	// (A2#2 — GitOps policy files, no separate policy-svc yet). This replaces the
	// hardcoded-APPROVE stub. Every decision cites the loaded policy's version hash.
	var pol engine.Policy
	if cfg.PolicyFile != "" {
		var perr error
		if pol, perr = policy.Load(cfg.PolicyFile); perr != nil {
			log.Error("policy load failed", "err", perr, "path", cfg.PolicyFile)
			os.Exit(1)
		}
		log.Info("policy loaded", "path", cfg.PolicyFile, "version", pol.Version, "predicates", len(pol.Predicates))
	} else {
		var perr error
		if pol, perr = policy.Default(); perr != nil {
			log.Error("default policy load failed", "err", perr)
			os.Exit(1)
		}
		log.Warn("using embedded default policy (set AUTHZ_POLICY_FILE for a custom policy)",
			"version", pol.Version, "predicates", len(pol.Predicates))
	}
	engineCore := engine.NewEngine(pol, signer.KeyID()).WithSigner(signer)

	// Control plane + bundle propagation (Task 2.2). When enabled, published policy
	// versions serve per-org via an in-memory cache refreshed off the hot path; the
	// static boot policy above stays the fallback for orgs that have not published
	// (file/GitOps mode). A background context (cancelled at shutdown) drives the
	// refresher. Boundary rule (TRD §3): the hot path reads only the local cache.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	var policySvc *policyctl.Service
	var bundleProvider *bundle.Provider
	if cfg.ControlPlaneEnabled {
		policyStore := policyctl.NewPostgresStore(pg.Pool)
		policySvc = policyctl.NewService(policyStore, signer)
		bundleProvider = bundle.NewProvider(policyStore, log, cfg.BundleLoadTimeout)
		engineCore = engineCore.WithProvider(bundleProvider)
		go bundleProvider.Run(bgCtx, cfg.BundleRefreshTTL)
		log.Info("control plane enabled", "bundle_refresh_ttl", cfg.BundleRefreshTTL.String())
	} else {
		log.Warn("control plane disabled; serving the static boot policy for every org")
	}
	authz := engineCore

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

	// Append-only audit log (Task 1.6): field-level encryption of amount/target when a
	// key is configured (else plaintext for dev), a Postgres source-of-truth store, and
	// an async in-proc writer so persistence never adds to the response latency.
	var encryptor audit.Encryptor = audit.NopEncryptor{}
	if cfg.AuditEncryptionKey != "" {
		key, derr := decodeSeed(cfg.AuditEncryptionKey)
		if derr != nil {
			log.Error("audit encryption key decode failed", "err", derr)
			os.Exit(1)
		}
		aes, aerr := audit.NewAESGCM(key)
		if aerr != nil {
			log.Error("audit encryption init failed", "err", aerr)
			os.Exit(1)
		}
		encryptor = aes
		log.Info("audit field-level encryption enabled")
	} else {
		log.Warn("audit field-level encryption DISABLED (no AUTHZ_AUDIT_ENCRYPTION_KEY); sensitive fields stored as plaintext")
	}
	auditStore := audit.NewPostgresStore(pg.Pool, encryptor)
	auditWriter := audit.NewWriter(auditStore, log, cfg.AuditQueueSize)
	auditWriter.Start()

	srv := server.New(log, build, authz, authn, limiter, tiers,
		server.Check{Name: "postgres", Ping: pg.Ping},
		server.Check{Name: "redis", Ping: rds.Ping},
	).WithKeys(func() any { return keyring.JWKS() }).
		WithAudit(auditWriter, auditStore, keyring.VerifyDecision, cfg.RetentionFor).
		WithIdempotency(idempotency.NewRedis(rds.Client, cfg.IdempotencyTTL))
	if policySvc != nil {
		srv = srv.WithControlPlane(policySvc, bundleProvider)
	}

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
	// Drain the async audit writer before the DB pool closes so queued records are
	// persisted. Anything still buffered on a hard crash is lost — the documented
	// MVP limitation that a durable queue (NATS/Kafka) removes (Task 1.6, §23).
	if err := auditWriter.Close(shutdownCtx); err != nil {
		log.Warn("audit writer drain incomplete on shutdown", "err", err)
	}
	log.Info("stopped")
}
