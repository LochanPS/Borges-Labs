package audit

import (
	"context"
	"crypto/rand"
	"log/slog"
	"testing"

	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

func sampleRecord(org, decID, agent string, verdict contractsv1.Verdict) *Record {
	req := contractsv1.AuthorizeRequest{
		AgentID:  agent,
		Action:   "payment.create",
		Amount:   "5000.00",
		Currency: "USD",
		Target:   contractsv1.Target{Type: contractsv1.TargetVendor, ID: "acme-supplies"},
	}
	dec := contractsv1.Decision{
		DecisionID:        decID,
		Verdict:           verdict,
		PolicyVersionHash: "pol_test_0001",
		Explanation:       contractsv1.Explanation{Summary: "ok", MatchedRules: []contractsv1.MatchedRule{}},
		Obligations:       []contractsv1.Obligation{},
		LatencyMs:         3,
		EvaluatedAt:       "2026-08-31T10:00:00Z",
		Signature:         contractsv1.Signature{Algorithm: "Ed25519", KeyID: "k1", Value: "AAAA", Canonicalization: "ti-decision-canon/1"},
	}
	return RecordFromDecision(org, "azn_test_key", req, dec)
}

func TestComputeRecordHash_Deterministic(t *testing.T) {
	r := sampleRecord("org1", "01HXYZ8K3M9QF0R7S2T4V6W8XA", "agent-a", contractsv1.VerdictApprove)
	h1, err := ComputeRecordHash(GenesisPrev, r)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h2, _ := ComputeRecordHash(GenesisPrev, r)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %q != %q", h1, h2)
	}
	// A different prev yields a different hash (chaining).
	h3, _ := ComputeRecordHash("rh_other", r)
	if h1 == h3 {
		t.Fatal("hash did not change with prev")
	}
	// A mutated field yields a different hash.
	r.Amount = "6000.00"
	h4, _ := ComputeRecordHash(GenesisPrev, r)
	if h1 == h4 {
		t.Fatal("hash did not change when amount changed")
	}
}

func TestVerifyChainLink_DetectsTamper(t *testing.T) {
	r := sampleRecord("org1", "01HXYZ8K3M9QF0R7S2T4V6W8XA", "agent-a", contractsv1.VerdictApprove)
	h, _ := ComputeRecordHash(GenesisPrev, r)
	r.PrevHash, r.RecordHash = GenesisPrev, h

	ok, err := VerifyChainLink(r)
	if err != nil || !ok {
		t.Fatalf("untampered link should verify: ok=%v err=%v", ok, err)
	}
	r.Verdict = contractsv1.VerdictDeny // tamper
	ok, _ = VerifyChainLink(r)
	if ok {
		t.Fatal("tampered record should fail chain link")
	}
}

func TestAESGCM_RoundTripAndPlaintextPassthrough(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	enc, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("new aesgcm: %v", err)
	}
	ct, err := enc.Encrypt("5000.00")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct == "5000.00" {
		t.Fatal("ciphertext equals plaintext")
	}
	pt, err := enc.Decrypt(ct)
	if err != nil || pt != "5000.00" {
		t.Fatalf("decrypt roundtrip: pt=%q err=%v", pt, err)
	}
	// A value stored without the cipher prefix reads back as-is.
	if got, _ := enc.Decrypt("plainval"); got != "plainval" {
		t.Fatalf("plaintext passthrough: %q", got)
	}
	// Nop cannot read a real ciphertext.
	if _, err := (NopEncryptor{}).Decrypt(ct); err == nil {
		t.Fatal("nop decrypt of ciphertext should error")
	}
}

func TestMemStore_ChainAndIdempotency(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore(nil)

	r1 := sampleRecord("org1", "01HXYZ8K3M9QF0R7S2T4V6W8X1", "agent-a", contractsv1.VerdictApprove)
	r2 := sampleRecord("org1", "01HXYZ8K3M9QF0R7S2T4V6W8X2", "agent-b", contractsv1.VerdictDeny)
	if err := s.Append(ctx, r1); err != nil {
		t.Fatalf("append r1: %v", err)
	}
	if err := s.Append(ctx, r2); err != nil {
		t.Fatalf("append r2: %v", err)
	}
	if r1.PrevHash != GenesisPrev {
		t.Errorf("r1 prev = %q, want genesis", r1.PrevHash)
	}
	if r2.PrevHash != r1.RecordHash {
		t.Errorf("chain broken: r2.prev=%q r1.hash=%q", r2.PrevHash, r1.RecordHash)
	}
	// Idempotent re-append is a no-op (no new seq).
	dup := sampleRecord("org1", "01HXYZ8K3M9QF0R7S2T4V6W8X1", "agent-a", contractsv1.VerdictApprove)
	if err := s.Append(ctx, dup); err != nil {
		t.Fatalf("re-append: %v", err)
	}
	page, _ := s.List(ctx, "org1", Filter{})
	if len(page.Records) != 2 {
		t.Fatalf("want 2 records after idempotent re-append, got %d", len(page.Records))
	}
}

func TestMemStore_FilterAndPaginate(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore(nil)
	for i := 0; i < 5; i++ {
		v := contractsv1.VerdictApprove
		if i%2 == 0 {
			v = contractsv1.VerdictDeny
		}
		id := "01HXYZ8K3M9QF0R7S2T4V6W8X" + string(rune('A'+i))
		if err := s.Append(ctx, sampleRecord("org1", id, "agent-a", v)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// Different org is isolated.
	_ = s.Append(ctx, sampleRecord("org2", "01HXYZ8K3M9QF0R7S2T4V6W8ZZ", "agent-a", contractsv1.VerdictApprove))

	// Filter by verdict.
	deny, _ := s.List(ctx, "org1", Filter{Verdict: contractsv1.VerdictDeny})
	if len(deny.Records) != 3 {
		t.Fatalf("want 3 DENY, got %d", len(deny.Records))
	}

	// Paginate 2 at a time over the org's 5 records.
	seen := 0
	var cursor int64
	for page := 0; page < 10; page++ {
		p, _ := s.List(ctx, "org1", Filter{Limit: 2, Cursor: cursor})
		seen += len(p.Records)
		if p.NextCursor == 0 {
			break
		}
		cursor = p.NextCursor
	}
	if seen != 5 {
		t.Fatalf("pagination saw %d records, want 5", seen)
	}
}

func TestMemStore_EncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	enc, _ := NewAESGCM(key)
	s := NewMemStore(enc)

	r := sampleRecord("org1", "01HXYZ8K3M9QF0R7S2T4V6W8XA", "agent-a", contractsv1.VerdictApprove)
	_ = s.Append(ctx, r)

	// The stored copy holds ciphertext; Get returns decrypted plaintext.
	if got := s.byOrg["org1"][0].Amount; got == "5000.00" {
		t.Fatal("amount stored as plaintext, expected ciphertext")
	}
	back, _ := s.Get(ctx, "org1", "01HXYZ8K3M9QF0R7S2T4V6W8XA")
	if back.Amount != "5000.00" {
		t.Fatalf("decrypted amount = %q, want 5000.00", back.Amount)
	}
	// Chain link still verifies over decrypted plaintext.
	if ok, err := VerifyChainLink(back); err != nil || !ok {
		t.Fatalf("chain link over decrypted record: ok=%v err=%v", ok, err)
	}
}

func TestWriter_AsyncPersistAndFlush(t *testing.T) {
	s := NewMemStore(nil)
	w := NewWriter(s, slog.Default(), 8)
	w.Start()

	for i := 0; i < 20; i++ {
		id := "01HXYZ8K3M9QF0R7S2T4V6W" + string(rune('A'+i%26)) + string(rune('a'+i))
		w.Enqueue(sampleRecord("org1", id, "agent-a", contractsv1.VerdictApprove))
	}
	w.Flush()

	page, _ := s.List(context.Background(), "org1", Filter{Limit: 200})
	if len(page.Records) != 20 {
		t.Fatalf("after flush want 20 persisted, got %d", len(page.Records))
	}
	if err := w.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Enqueue after close persists inline (no drop).
	w.Enqueue(sampleRecord("org1", "01HXYZ8K3M9QF0R7S2T4V6W8ZZ", "agent-a", contractsv1.VerdictApprove))
	if _, err := s.Get(context.Background(), "org1", "01HXYZ8K3M9QF0R7S2T4V6W8ZZ"); err != nil {
		t.Fatalf("post-close inline persist failed: %v", err)
	}
}
