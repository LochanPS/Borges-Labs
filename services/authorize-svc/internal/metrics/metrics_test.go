package metrics

import (
	"strings"
	"testing"
)

func TestMetrics_WriteText(t *testing.T) {
	m := New("test-1")
	m.RecordDecision("APPROVE", 3)
	m.RecordDecision("APPROVE", 12)
	m.RecordDecision("DENY", 40)
	m.RecordRateLimited()

	var sb strings.Builder
	m.WriteText(&sb)
	out := sb.String()

	for _, want := range []string{
		`authz_build_info{version="test-1"} 1`,
		`authz_decisions_total{verdict="APPROVE"} 2`,
		`authz_decisions_total{verdict="DENY"} 1`,
		`authz_rate_limited_total 1`,
		`authz_decision_latency_ms_count 3`,
		`authz_decision_latency_ms_sum 55`,
		`# TYPE authz_decision_latency_ms histogram`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}
}

func TestMetrics_HistogramBucketsCumulative(t *testing.T) {
	m := New("x")
	m.RecordDecision("APPROVE", 3) // <=5, <=10, ... buckets
	var sb strings.Builder
	m.WriteText(&sb)
	out := sb.String()
	// le="1" and le="2" should be 0; le="5" and above should be 1.
	if !strings.Contains(out, `authz_decision_latency_ms_bucket{le="2"} 0`) {
		t.Errorf("expected le=2 bucket 0\n%s", out)
	}
	if !strings.Contains(out, `authz_decision_latency_ms_bucket{le="5"} 1`) {
		t.Errorf("expected le=5 bucket 1\n%s", out)
	}
	if !strings.Contains(out, `authz_decision_latency_ms_bucket{le="+Inf"} 1`) {
		t.Errorf("expected +Inf bucket 1\n%s", out)
	}
}
