package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/audit"
	"github.com/trust-infra/authorize-svc/internal/auth"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// signedGet builds a signed GET request. The HMAC is over the PATH only (no query),
// matching what the auth middleware verifies (r.URL.Path), with an empty body.
func (h *authHarness) signedGet(t *testing.T, pathWithQuery string) *http.Request {
	t.Helper()
	u, err := url.Parse(pathWithQuery)
	if err != nil {
		t.Fatalf("parse path: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, h.ts.URL+pathWithQuery, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := newNonce(t)
	req.Header.Set("Authorization", "Bearer "+h.active)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", auth.Sign(h.active, http.MethodGet, u.Path, ts, nonce, nil))
	return req
}

// authorizeAndWait POSTs an authorize request and blocks until the decision is
// persisted by the async writer, returning the authorize response decision.
func authorizeAndWait(t *testing.T, h *authHarness, body []byte) contractsv1.Decision {
	t.Helper()
	resp, respBody := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", body, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d; body: %s", resp.StatusCode, respBody)
	}
	var dec contractsv1.Decision
	if err := json.Unmarshal(respBody, &dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	// Poll the store until the async write lands (no drop; just not-yet-written).
	for i := 0; i < 200; i++ {
		if _, err := h.store.Get(context.Background(), h.orgID, dec.DecisionID); err == nil {
			return dec
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("decision %s never persisted", dec.DecisionID)
	return dec
}

func getDecision(t *testing.T, h *authHarness, id string) (*http.Response, contractsv1.Decision) {
	t.Helper()
	resp, body := do(t, h.signedGet(t, "/v1/decisions/"+id))
	var dec contractsv1.Decision
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &dec); err != nil {
			t.Fatalf("decode decision: %v; body: %s", err, body)
		}
	}
	return resp, dec
}

// ACCEPTANCE: a decision is retrievable with signature_verified:true, carries a
// record_hash, and its stored latency_ms equals the authorize response's — proving
// the async audit write did not inflate the request's measured latency.
func TestDecisions_RetrievableAndVerified(t *testing.T) {
	h := newAuthHarness(t)
	decisionSchema := compileContract(t, decisionSchemaID)

	authzDec := authorizeAndWait(t, h, validAuthorizeBody)

	resp, got := getDecision(t, h, authzDec.DecisionID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want 200", resp.StatusCode)
	}

	body, _ := json.Marshal(got)
	validateAgainst(t, decisionSchema, body)

	if got.SignatureVerified == nil || !*got.SignatureVerified {
		t.Fatalf("signature_verified = %v, want true", got.SignatureVerified)
	}
	if got.RecordHash == "" {
		t.Error("record_hash missing on stored decision")
	}
	if got.LatencyMs != authzDec.LatencyMs {
		t.Errorf("stored latency_ms = %d, want %d (audit write must not change it)", got.LatencyMs, authzDec.LatencyMs)
	}
	if got.Verdict != authzDec.Verdict {
		t.Errorf("verdict = %q, want %q", got.Verdict, authzDec.Verdict)
	}
}

// ACCEPTANCE: mutating a stored row breaks the chain and/or signature, flipping
// signature_verified to false. Two cases: a signed field (verdict) and a
// hash-covered but unsigned field (amount).
func TestDecisions_TamperBreaksVerification(t *testing.T) {
	h := newAuthHarness(t)

	t.Run("signed field", func(t *testing.T) {
		dec := authorizeAndWait(t, h, validAuthorizeBody)
		ok := h.store.Mutate(h.orgID, dec.DecisionID, func(r *audit.Record) {
			r.Verdict = contractsv1.VerdictDeny // was APPROVE; a signed field
		})
		if !ok {
			t.Fatal("mutate did not find the record")
		}
		_, got := getDecision(t, h, dec.DecisionID)
		if got.SignatureVerified == nil || *got.SignatureVerified {
			t.Fatalf("signature_verified = %v, want false after tamper", got.SignatureVerified)
		}
	})

	t.Run("hash-covered unsigned field", func(t *testing.T) {
		body := []byte(`{
		  "agent_id": "agent-x", "action": "payment.create", "amount": "10.00",
		  "currency": "USD", "target": { "type": "vendor", "id": "v1" },
		  "idempotency_key": "idem_01HXYZ8K3M9QF0R7S2T4V6W8XB"
		}`)
		dec := authorizeAndWait(t, h, body)
		ok := h.store.Mutate(h.orgID, dec.DecisionID, func(r *audit.Record) {
			r.Amount = "999999.00" // not signed, but covered by record_hash
		})
		if !ok {
			t.Fatal("mutate did not find the record")
		}
		_, got := getDecision(t, h, dec.DecisionID)
		if got.SignatureVerified == nil || *got.SignatureVerified {
			t.Fatalf("signature_verified = %v, want false after amount tamper", got.SignatureVerified)
		}
	})
}

// ACCEPTANCE: list is paginated and filterable by agent/verdict/date, org-scoped.
func TestDecisions_ListFilterAndPaginate(t *testing.T) {
	h := newAuthHarness(t)

	// Seed a mix of agents/verdicts. The stub always APPROVES, so exercise the agent
	// filter across two agents and pagination across the full set.
	agents := []string{"agent-a", "agent-b"}
	total := 6
	for i := 0; i < total; i++ {
		body := []byte(`{
		  "agent_id": "` + agents[i%2] + `", "action": "payment.create", "amount": "1.00",
		  "currency": "USD", "target": { "type": "vendor", "id": "v" },
		  "idempotency_key": "idem_seed_` + strconv.Itoa(i) + `_padding"
		}`)
		authorizeAndWait(t, h, body)
	}

	// Filter by agent-a: exactly half.
	resp, page := listDecisions(t, h, "/v1/decisions?agent_id=agent-a")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	if len(page.Data) != total/2 {
		t.Fatalf("agent-a count = %d, want %d", len(page.Data), total/2)
	}
	for _, d := range page.Data {
		if d.SignatureVerified == nil || !*d.SignatureVerified {
			t.Error("listed decision not verified")
		}
	}

	// Verdict filter that matches nothing (stub only APPROVEs).
	_, denies := listDecisions(t, h, "/v1/decisions?verdict=DENY")
	if len(denies.Data) != 0 {
		t.Fatalf("DENY count = %d, want 0", len(denies.Data))
	}

	// Paginate the full set 2 at a time.
	seen := 0
	next := ""
	for i := 0; i < 20; i++ {
		path := "/v1/decisions?limit=2"
		if next != "" {
			path += "&cursor=" + url.QueryEscape(next)
		}
		_, p := listDecisions(t, h, path)
		seen += len(p.Data)
		if p.NextCursor == nil {
			break
		}
		next = *p.NextCursor
	}
	if seen != total {
		t.Fatalf("pagination saw %d, want %d", seen, total)
	}
}

func listDecisions(t *testing.T, h *authHarness, pathWithQuery string) (*http.Response, listPage) {
	t.Helper()
	resp, body := do(t, h.signedGet(t, pathWithQuery))
	var page listPage
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("decode list: %v; body: %s", err, body)
		}
	}
	return resp, page
}
