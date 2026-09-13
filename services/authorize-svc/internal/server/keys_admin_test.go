package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type keyView struct {
	ID       string `json:"id"`
	Prefix   string `json:"prefix"`
	OrgID    string `json:"org_id"`
	Env      string `json:"env"`
	IsActive bool   `json:"is_active"`
	Shadow   bool   `json:"shadow"`
	Secret   string `json:"secret"`
}

// Create a key, use it to authenticate, list it, revoke it, and confirm the revoked
// key is refused 403 (Task 5.1: API keys create-once + revoke).
func TestKeys_CreateUseListRevoke(t *testing.T) {
	h := newCPHarness(t)

	// Create an enforcing test key.
	body := mustJSON(t, map[string]any{"env": "test", "shadow": false})
	resp, b := do(t, h.sign(t, http.MethodPost, "/v1/keys", body, h.active))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d; body: %s", resp.StatusCode, b)
	}
	var created keyView
	if err := json.Unmarshal(b, &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.Secret == "" || !strings.HasPrefix(created.Secret, "azn_test_") {
		t.Fatalf("expected a test secret, got %q", created.Secret)
	}
	if !created.IsActive || created.Shadow {
		t.Fatalf("expected active, non-shadow key: %+v", created)
	}
	if created.OrgID != h.org {
		t.Fatalf("key org = %q, want %q", created.OrgID, h.org)
	}

	// The brand-new key authenticates immediately.
	resp, b = do(t, h.sign(t, http.MethodGet, "/v1/keys", nil, created.Secret))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("new key auth status = %d; body: %s", resp.StatusCode, b)
	}

	// List includes the created key.
	resp, b = do(t, h.sign(t, http.MethodGet, "/v1/keys", nil, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d; body: %s", resp.StatusCode, b)
	}
	var list struct {
		Data []keyView `json:"data"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, k := range list.Data {
		if k.ID == created.ID {
			found = true
		}
		if k.Secret != "" {
			t.Fatalf("list must never include a secret: %+v", k)
		}
	}
	if !found {
		t.Fatalf("created key %s not in list", created.ID)
	}

	// Revoke it.
	resp, b = do(t, h.sign(t, http.MethodPost, "/v1/keys/"+created.ID+"/revoke", nil, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d; body: %s", resp.StatusCode, b)
	}
	var revoked keyView
	_ = json.Unmarshal(b, &revoked)
	if revoked.IsActive {
		t.Fatalf("revoked key still active: %+v", revoked)
	}

	// The revoked key is a valid credential but refused 403.
	resp, _ = do(t, h.sign(t, http.MethodGet, "/v1/keys", nil, created.Secret))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked key auth status = %d, want 403", resp.StatusCode)
	}
}

func TestKeys_RevokeUnknown(t *testing.T) {
	h := newCPHarness(t)
	resp, _ := do(t, h.sign(t, http.MethodPost, "/v1/keys/azn_test_deadbeefdeadbeef/revoke", nil, h.active))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("revoke unknown status = %d, want 404", resp.StatusCode)
	}
}

func TestKeys_CreateValidatesEnv(t *testing.T) {
	h := newCPHarness(t)
	body := mustJSON(t, map[string]any{"env": "prod"})
	resp, _ := do(t, h.sign(t, http.MethodPost, "/v1/keys", body, h.active))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad env status = %d, want 400", resp.StatusCode)
	}
}
