// Package config loads runtime configuration from the environment.
// No business logic — just the knobs the service needs to boot, connect, and
// stamp decisions.
package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds decision-plane service configuration.
type Config struct {
	// Addr is the HTTP listen address, e.g. ":8080".
	Addr string
	// DatabaseURL is the Postgres DSN (source of truth store — TRD §13).
	DatabaseURL string
	// RedisURL is the Redis connection URL (hot-path state — TRD §13).
	RedisURL string
	// LogLevel is debug|info|warn|error.
	LogLevel string
	// ShutdownTimeout bounds graceful drain of in-flight requests on SIGTERM.
	ShutdownTimeout time.Duration
	// PolicyVersionHash is a legacy override for the decision plane's cited policy
	// version. It is only used by the Stub authorizer; the real engine derives the
	// version from the loaded policy file (see PolicyFile). Kept for the stub and
	// early smoke tests.
	PolicyVersionHash string
	// PolicyFile is the path to the JSON policy the engine loads (A2#2 — GitOps
	// policy files, no separate policy-svc yet). Empty => the binary's embedded
	// default policy (internal/policy/default.policy.json).
	PolicyFile string
	// IdempotencyTTL is how long a decision is cached by its idempotency key so a
	// repeated authorize request returns the same decision (Task 1.7).
	IdempotencyTTL time.Duration
	// SigningKeyID names the Ed25519 key a decision is signed under (TRD §11).
	SigningKeyID string
	// --- control plane / bundle propagation (Task 2.2) ---

	// ControlPlaneEnabled mounts the /v1/policies authoring endpoints and wires the
	// per-org bundle provider into the engine. Default true. Disable to run a pure
	// decision node that only serves the static boot policy (file/GitOps mode).
	ControlPlaneEnabled bool
	// BundleRefreshTTL is how often the decision plane re-reads each org's active
	// version to converge on cross-instance publishes (A#4). Same-process publishes
	// converge immediately via cache invalidation.
	BundleRefreshTTL time.Duration
	// BundleLoadTimeout bounds a cold-miss / refresh bundle load so a slow control-plane
	// store cannot stall the first request for an org.
	BundleLoadTimeout time.Duration
	// HoldTTL is how long a two-phase budget hold lives before auto-release (Task 3.1).
	// A caller must capture or void within it; otherwise the reservation is released.
	HoldTTL time.Duration
	// BudgetReconcileInterval is how often the reconciler releases TTL-expired holds
	// back to the budget counter (Task 3.2).
	BudgetReconcileInterval time.Duration

	// SigningPrivateKey is the base64 (std or url) 32-byte Ed25519 seed the decision
	// signer loads (Task 1.5). Empty in dev => a key is generated at boot and its
	// public half is published at /v1/keys/public. Production supplies this from the
	// secret manager; KMS/HSM custody is a Prod TODO.
	SigningPrivateKey string

	// HMACMaxSkew is the largest allowed clock difference between a request's
	// signed timestamp and server time (TRD §11 request signing). Bounds replay.
	HMACMaxSkew time.Duration
	// NonceTTL is how long a per-key nonce is remembered for replay protection.
	// Must be >= 2*HMACMaxSkew; the auth layer enforces that floor.
	NonceTTL time.Duration
	// KeyCacheTTL is the Redis cache lifetime for key -> org lookups (TRD §11).
	KeyCacheTTL time.Duration

	// --- audit log (Task 1.6, ROADMAP A#10) ---

	// AuditEncryptionKey is the base64 (std/url) or hex 32-byte AES-256-GCM key used
	// for field-level encryption of sensitive audit fields (amount/target). Empty =>
	// fields are stored as plaintext (dev/CI). Production supplies this from the
	// secret manager; KMS custody is a Prod TODO.
	AuditEncryptionKey string
	// AuditQueueSize is the depth of the in-proc async-write buffer. 0 => package
	// default. The async writer never drops; a full buffer applies backpressure to
	// the (already-sent) response's goroutine only.
	AuditQueueSize int
	// AuditRetentionDefault is the fallback retention for a tier not in the per-tier
	// table below. Retention marks when the sensitive ciphertext becomes eligible for
	// crypto-shred; it never deletes rows (append-only, A#10).
	AuditRetentionDefault time.Duration
	// AuditRetentionByTier overrides retention per caller tier.
	AuditRetentionByTier map[string]time.Duration
}

// RetentionFor resolves the audit retention window for a caller tier, falling back
// to AuditRetentionDefault when the tier is not explicitly configured.
func (c Config) RetentionFor(tier string) time.Duration {
	if d, ok := c.AuditRetentionByTier[tier]; ok {
		return d
	}
	return c.AuditRetentionDefault
}

// Load reads configuration from the environment, applying local-dev defaults
// that line up with deploy/docker-compose.yml.
func Load() Config {
	return Config{
		Addr:                    env("AUTHZ_ADDR", ":8080"),
		DatabaseURL:             env("DATABASE_URL", "postgres://authz:authz@localhost:5432/authz?sslmode=disable"),
		RedisURL:                env("REDIS_URL", "redis://localhost:6379/0"),
		LogLevel:                env("LOG_LEVEL", "info"),
		ShutdownTimeout:         envDuration("AUTHZ_SHUTDOWN_TIMEOUT", 10*time.Second),
		PolicyVersionHash:       env("AUTHZ_POLICY_VERSION", "pol_stub_0000000000000000000000000000000000000000000000000000000000000000"),
		PolicyFile:              env("AUTHZ_POLICY_FILE", ""),
		IdempotencyTTL:          envDuration("AUTHZ_IDEMPOTENCY_TTL", 24*time.Hour),
		ControlPlaneEnabled:     envBool("AUTHZ_CONTROL_PLANE_ENABLED", true),
		BundleRefreshTTL:        envDuration("AUTHZ_BUNDLE_REFRESH_TTL", 5*time.Second),
		BundleLoadTimeout:       envDuration("AUTHZ_BUNDLE_LOAD_TIMEOUT", 2*time.Second),
		HoldTTL:                 envDuration("AUTHZ_HOLD_TTL", 15*time.Minute),
		BudgetReconcileInterval: envDuration("AUTHZ_BUDGET_RECONCILE_INTERVAL", time.Minute),
		SigningKeyID:            env("AUTHZ_SIGNING_KEY_ID", "azn-sign-dev"),
		SigningPrivateKey:       env("AUTHZ_SIGNING_PRIVATE_KEY", ""),
		HMACMaxSkew:             envDuration("AUTHZ_HMAC_MAX_SKEW", 5*time.Minute),
		NonceTTL:                envDuration("AUTHZ_NONCE_TTL", 10*time.Minute),
		KeyCacheTTL:             envDuration("AUTHZ_KEY_CACHE_TTL", 5*time.Minute),

		AuditEncryptionKey:    env("AUTHZ_AUDIT_ENCRYPTION_KEY", ""),
		AuditQueueSize:        envInt("AUTHZ_AUDIT_QUEUE_SIZE", 1024),
		AuditRetentionDefault: envDuration("AUTHZ_AUDIT_RETENTION_DEFAULT", 365*24*time.Hour),
		// Per-tier retention (A#10). Higher tiers keep audit longer; adjust to
		// regulatory needs. These are the shipped defaults, not a hard limit.
		AuditRetentionByTier: map[string]time.Duration{
			"free":       90 * 24 * time.Hour,
			"default":    365 * 24 * time.Hour,
			"pro":        730 * 24 * time.Hour,
			"enterprise": 7 * 365 * 24 * time.Hour,
		},
	}
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
