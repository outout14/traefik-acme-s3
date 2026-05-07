package certcloset

import (
	"testing"
	"time"
)

func TestLoadFailureState_Empty(t *testing.T) {
	c := newTestCloset(t, false)
	s, err := c.LoadFailureState()
	if err != nil {
		t.Fatalf("LoadFailureState: %v", err)
	}
	if s.LastFailure == nil {
		t.Fatal("LastFailure map must be initialized")
	}
	if len(s.LastFailure) != 0 {
		t.Fatalf("want empty map, got %d entries", len(s.LastFailure))
	}
}

func TestStoreLoadFailureState(t *testing.T) {
	c := newTestCloset(t, false)
	state := &FailureState{LastFailure: map[string]string{
		"example.com": time.Now().Format(time.RFC3339),
		"other.com":   time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
	}}
	if err := c.StoreFailureState(state); err != nil {
		t.Fatalf("StoreFailureState: %v", err)
	}
	got, err := c.LoadFailureState()
	if err != nil {
		t.Fatalf("LoadFailureState: %v", err)
	}
	if len(got.LastFailure) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got.LastFailure))
	}
	if _, ok := got.LastFailure["example.com"]; !ok {
		t.Error("example.com missing after reload")
	}
}

func TestStoreLoadRolloverState(t *testing.T) {
	c := newTestCloset(t, false)
	now := time.Now().Truncate(time.Second).UTC()
	want := &RolloverState{
		Phase:          RolloverPhasePrePublishing,
		OldTLSAHex:     "aabbcc",
		NewTLSAHex:     "ddeeff",
		PhaseStartedAt: now,
		TLSATTLSeconds: 300,
		SyncLagSeconds: 300,
	}
	if err := c.StoreRolloverState("example.com", want); err != nil {
		t.Fatalf("StoreRolloverState: %v", err)
	}
	got, exists, err := c.LoadRolloverState("example.com")
	if err != nil {
		t.Fatalf("LoadRolloverState: %v", err)
	}
	if !exists {
		t.Fatal("want exists=true")
	}
	if got.Phase != want.Phase {
		t.Errorf("phase: want %q got %q", want.Phase, got.Phase)
	}
	if got.OldTLSAHex != want.OldTLSAHex {
		t.Errorf("old TLSA: want %q got %q", want.OldTLSAHex, got.OldTLSAHex)
	}
	if got.NewTLSAHex != want.NewTLSAHex {
		t.Errorf("new TLSA: want %q got %q", want.NewTLSAHex, got.NewTLSAHex)
	}
	if !got.PhaseStartedAt.Equal(now) {
		t.Errorf("phase started at: want %v got %v", now, got.PhaseStartedAt)
	}
}

func TestLoadRolloverState_NotFound(t *testing.T) {
	c := newTestCloset(t, false)
	_, exists, err := c.LoadRolloverState("nope.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Fatal("want exists=false for missing rollover state")
	}
}

func TestDeleteRolloverState(t *testing.T) {
	c := newTestCloset(t, false)
	state := &RolloverState{Phase: RolloverPhasePrePublishing, NewTLSAHex: "abc", PhaseStartedAt: time.Now()}
	if err := c.StoreRolloverState("example.com", state); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteRolloverState("example.com"); err != nil {
		t.Fatalf("DeleteRolloverState: %v", err)
	}
	_, exists, err := c.LoadRolloverState("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("rollover state must be gone after delete")
	}
}

func TestStorePendingKey_RoundTrip(t *testing.T) {
	c := newTestCloset(t, false)
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nfakepemdata\n-----END EC PRIVATE KEY-----")

	if err := c.StorePendingKey("example.com", keyPEM); err != nil {
		t.Fatalf("StorePendingKey: %v", err)
	}
	got, err := c.LoadPendingKey("example.com")
	if err != nil {
		t.Fatalf("LoadPendingKey: %v", err)
	}
	if string(got) != string(keyPEM) {
		t.Errorf("key mismatch after encrypt/decrypt round-trip")
	}
}

func TestDeletePendingKey(t *testing.T) {
	c := newTestCloset(t, false)
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----")
	if err := c.StorePendingKey("example.com", keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePendingKey("example.com"); err != nil {
		t.Fatalf("DeletePendingKey: %v", err)
	}
	_, err := c.LoadPendingKey("example.com")
	if err == nil {
		t.Fatal("expected error loading deleted pending key")
	}
}
