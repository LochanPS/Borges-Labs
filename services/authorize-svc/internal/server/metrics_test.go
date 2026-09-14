package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A successful authorize is reflected in GET /metrics: the verdict counter increments
// and the latency histogram observes one sample (TRD §18).
func TestMetrics_EndpointReflectsDecision(t *testing.T) {
	h := newAuthHarness(t)

	resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d; body: %s", resp.StatusCode, body)
	}

	mResp, err := http.Get(h.ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer mResp.Body.Close()
	if ct := mResp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("metrics content-type = %q, want text/plain", ct)
	}
	raw, _ := io.ReadAll(mResp.Body)
	out := string(raw)

	for _, want := range []string{
		`authz_decisions_total{verdict="APPROVE"} 1`,
		`authz_decision_latency_ms_count 1`,
		`authz_build_info`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\n---\n%s", want, out)
		}
	}
}
