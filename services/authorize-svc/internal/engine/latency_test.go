package engine

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// latencyPolicy is a realistic full policy (all six local predicates) so the
// measured decision path is representative, not a one-rule best case.
func latencyPolicy() Policy {
	return Policy{
		Version: "pol_latency_bench",
		Predicates: []Predicate{
			NewPerTransactionLimit("lim", nil, "10000.00", "USD"),
			NewVendorAllowlist("allow", nil, []string{"acme", "globex", "initech"}),
			NewVendorBlocklist("block", nil, []string{"evilcorp"}),
			NewAgentPermission("perm", nil, []string{"payment.create", "payment.capture"}, nil),
			NewTimeWindow("hours", nil, 0, 0, nil), // full-day: always satisfied
			NewJurisdictionCurrency("juris", nil, map[string][]string{"US": {"USD"}, "GB": {"GBP"}}),
		},
	}
}

func latencyRequest() contractsv1.AuthorizeRequest {
	return contractsv1.AuthorizeRequest{
		AgentID:  "procurement-agent",
		Action:   "payment.create",
		Amount:   "4999.00",
		Currency: "USD",
		Target:   contractsv1.Target{Type: contractsv1.TargetVendor, ID: "acme"},
	}
}

func realSigner(t testing.TB) *signing.Signer {
	t.Helper()
	kr := signing.NewKeyring()
	if _, err := kr.GenerateActive(); err != nil {
		t.Fatalf("gen signing key: %v", err)
	}
	s, err := kr.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

// TestDecisionLatency_P99 measures the local-decision latency (full predicate
// evaluation + Ed25519 signing) and reports p50/p99/max, asserting the MVP target
// of p99 < 50ms (ROADMAP Task 1.7 acceptance). This is the compute path only — no
// network, no store — which is what "local-decision latency" denotes.
func TestDecisionLatency_P99(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement skipped in -short")
	}
	eng := NewEngine(latencyPolicy(), "bench-key").WithSigner(realSigner(t))
	req := latencyRequest()
	ctx := context.Background()

	const iterations = 3000
	samples := make([]time.Duration, 0, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		if _, err := eng.Authorize(ctx, req); err != nil {
			t.Fatalf("authorize: %v", err)
		}
		samples = append(samples, time.Since(start))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })

	p := func(q float64) time.Duration {
		idx := int(float64(len(samples)) * q)
		if idx >= len(samples) {
			idx = len(samples) - 1
		}
		return samples[idx]
	}
	p50, p99, max := p(0.50), p(0.99), samples[len(samples)-1]
	t.Logf("local-decision latency over %d iters: p50=%v p99=%v max=%v", iterations, p50, p99, max)

	const target = 50 * time.Millisecond
	if p99 > target {
		t.Errorf("p99 = %v exceeds MVP target %v", p99, target)
	}
}

// BenchmarkDecision reports the mean decision-path cost (go test -bench=Decision).
func BenchmarkDecision(b *testing.B) {
	eng := NewEngine(latencyPolicy(), "bench-key").WithSigner(realSigner(b))
	req := latencyRequest()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.Authorize(ctx, req); err != nil {
			b.Fatalf("authorize: %v", err)
		}
	}
}
