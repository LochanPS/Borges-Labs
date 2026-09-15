package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const testProvisionToken = "test-provision-token"

// provisionReq POSTs to /v1/provision/keys with the given token (platform auth, no HMAC).
func (h *cpHarness) provisionReq(t *testing.T, token string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/provision/keys", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Provision-Token", token)
	}
	return do(t, req)
}

// Onboarding bootstrap (M1): the platform mints a brand-new org's first key, and that
// key immediately authenticates and is scoped to the new org.
func TestProvision_BootstrapsNewOrgKey(t *testing.T) {
	h := newCPHarness(t)

	body := mustJSON(t, map[string]any{"org_id": "org_new", "env": "test", "shadow": false})
	resp, b := h.provisionReq(t, testProvisionToken, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("provision status = %d; body: %s", resp.StatusCode, b)
	}
	var created keyView
	if err := json.Unmarshal(b, &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.Secret == "" || !strings.HasPrefix(created.Secret, "azn_test_") {
		t.Fatalf("expected a test secret; got %q", created.Secret)
	}
	if created.OrgID != "org_new" {
		t.Fatalf("org = %q, want org_new", created.OrgID)
	}

	// The freshly provisioned key authenticates and lists only its own org's keys.
	resp, b = do(t, h.sign(t, http.MethodGet, "/v1/keys", nil, created.Secret))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("new org key auth status = %d; body: %s", resp.StatusCode, b)
	}
	var list struct {
		Data []keyView `json:"data"`
	}
	_ = json.Unmarshal(b, &list)
	for _, k := range list.Data {
		if k.OrgID != "org_new" {
			t.Fatalf("cross-org leak: listed key for org %q", k.OrgID)
		}
	}
}

func TestProvision_WrongTokenRejected(t *testing.T) {
	h := newCPHarness(t)
	body := mustJSON(t, map[string]any{"org_id": "org_x", "env": "test"})

	resp, _ := h.provisionReq(t, "wrong-token", body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", resp.StatusCode)
	}
	resp, _ = h.provisionReq(t, "", body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", resp.StatusCode)
	}
}

func TestProvision_ValidatesInput(t *testing.T) {
	h := newCPHarness(t)
	// missing org_id
	resp, _ := h.provisionReq(t, testProvisionToken, mustJSON(t, map[string]any{"env": "test"}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing org_id status = %d, want 400", resp.StatusCode)
	}
	// bad env
	resp, _ = h.provisionReq(t, testProvisionToken, mustJSON(t, map[string]any{"org_id": "o", "env": "prod"}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad env status = %d, want 400", resp.StatusCode)
	}
}
