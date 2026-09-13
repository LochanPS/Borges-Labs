package auth

import (
	"context"
	"testing"
	"time"
)

func TestMemKeyAdmin_CreateListRevoke(t *testing.T) {
	ctx := context.Background()
	store := NewMemKeyStore()

	gk, err := NewKey(EnvTest, "org1", "default")
	if err != nil {
		t.Fatalf("new key: %v", err)
	}
	now := time.Now().UTC()
	if err := store.CreateKey(ctx, gk.Record, now); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Created key authenticates via the hot-path lookup.
	if _, err := store.LookupByID(ctx, gk.Record.KeyID); err != nil {
		t.Fatalf("lookup created key: %v", err)
	}

	// A key from another org is not listed.
	other, _ := NewKey(EnvTest, "org2", "default")
	_ = store.CreateKey(ctx, other.Record, now)

	list, err := store.ListKeys(ctx, "org1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].KeyID != gk.Record.KeyID {
		t.Fatalf("org1 list = %+v, want just the org1 key", list)
	}

	// Revoke within the wrong org fails; within the right org flips status.
	if _, err := store.RevokeKey(ctx, "org2", gk.Record.KeyID, now); err != ErrKeyNotFound {
		t.Fatalf("cross-org revoke err = %v, want ErrKeyNotFound", err)
	}
	info, err := store.RevokeKey(ctx, "org1", gk.Record.KeyID, now)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if info.Status != StatusRevoked || info.RevokedAt == nil {
		t.Fatalf("revoked info = %+v", info)
	}
	rec, _ := store.LookupByID(ctx, gk.Record.KeyID)
	if rec.Status != StatusRevoked {
		t.Fatalf("record status = %q, want revoked", rec.Status)
	}
}
