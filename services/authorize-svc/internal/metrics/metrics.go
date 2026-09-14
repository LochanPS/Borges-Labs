// Package metrics is a tiny, dependency-free metrics registry that exposes the
// decision plane's operational signals (TRD §18) in Prometheus text exposition format
// at GET /metrics. It is intentionally minimal — a handful of counters and one
// histogram — so the service pulls in no metrics client library. A production
// deployment can scrape this endpoint directly.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// latencyBucketsMs are the upper bounds (inclusive) of the decision-latency histogram,
// in milliseconds. Chosen to straddle the single-digit-ms happy path and flag the tail.
var latencyBucketsMs = []float64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000}

// Metrics holds the process-wide counters. All methods are safe for concurrent use.
type Metrics struct {
	mu sync.Mutex

	version string

	decisions   map[string]int64 // verdict -> count
	rateLimited int64

	// Decision-latency histogram (ms): cumulative bucket counts + sum + count.
	buckets    []float64
	bucketHits []int64
	latencySum float64
	latencyN   int64
}

// New builds an empty registry. version labels the build_info gauge.
func New(version string) *Metrics {
	return &Metrics{
		version:    version,
		decisions:  make(map[string]int64),
		buckets:    latencyBucketsMs,
		bucketHits: make([]int64, len(latencyBucketsMs)),
	}
}

// RecordDecision counts one decision by verdict and observes its latency (ms).
func (m *Metrics) RecordDecision(verdict string, latencyMs int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if verdict == "" {
		verdict = "UNKNOWN"
	}
	m.decisions[verdict]++
	v := float64(latencyMs)
	m.latencySum += v
	m.latencyN++
	for i, ub := range m.buckets {
		if v <= ub {
			m.bucketHits[i]++
		}
	}
}

// RecordRateLimited counts one request rejected by the rate limiter (429).
func (m *Metrics) RecordRateLimited() {
	m.mu.Lock()
	m.rateLimited++
	m.mu.Unlock()
}

// WriteText renders the current metrics in Prometheus text exposition format.
func (m *Metrics) WriteText(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Fprintf(w, "# HELP authz_build_info Build metadata.\n")
	fmt.Fprintf(w, "# TYPE authz_build_info gauge\n")
	fmt.Fprintf(w, "authz_build_info{version=%q} 1\n", m.version)

	fmt.Fprintf(w, "# HELP authz_decisions_total Decisions produced, by verdict.\n")
	fmt.Fprintf(w, "# TYPE authz_decisions_total counter\n")
	verdicts := make([]string, 0, len(m.decisions))
	for v := range m.decisions {
		verdicts = append(verdicts, v)
	}
	sort.Strings(verdicts)
	for _, v := range verdicts {
		fmt.Fprintf(w, "authz_decisions_total{verdict=%q} %d\n", v, m.decisions[v])
	}

	fmt.Fprintf(w, "# HELP authz_rate_limited_total Requests rejected by the rate limiter.\n")
	fmt.Fprintf(w, "# TYPE authz_rate_limited_total counter\n")
	fmt.Fprintf(w, "authz_rate_limited_total %d\n", m.rateLimited)

	fmt.Fprintf(w, "# HELP authz_decision_latency_ms Decision evaluation latency in milliseconds.\n")
	fmt.Fprintf(w, "# TYPE authz_decision_latency_ms histogram\n")
	for i, ub := range m.buckets {
		fmt.Fprintf(w, "authz_decision_latency_ms_bucket{le=\"%g\"} %d\n", ub, m.bucketHits[i])
	}
	fmt.Fprintf(w, "authz_decision_latency_ms_bucket{le=\"+Inf\"} %d\n", m.latencyN)
	fmt.Fprintf(w, "authz_decision_latency_ms_sum %g\n", m.latencySum)
	fmt.Fprintf(w, "authz_decision_latency_ms_count %d\n", m.latencyN)
}
