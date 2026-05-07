package app

import (
	"fmt"
	"testing"
	"time"

	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
)

var testApp = &App{}

func TestIsInBackoffNilState(t *testing.T) {
	if testApp.isInBackoff(nil, "x.com", 60) {
		t.Fatal("nil state must return false")
	}
}

func TestIsInBackoffZeroMinutes(t *testing.T) {
	s := &certcloset.FailureState{LastFailure: map[string]string{
		"x.com": time.Now().Format(time.RFC3339),
	}}
	if testApp.isInBackoff(s, "x.com", 0) {
		t.Fatal("0 backoff minutes must return false")
	}
}

func TestIsInBackoffDomainNotInState(t *testing.T) {
	s := &certcloset.FailureState{LastFailure: make(map[string]string)}
	if testApp.isInBackoff(s, "x.com", 60) {
		t.Fatal("unknown domain must return false")
	}
}

func TestIsInBackoffRecentFailure(t *testing.T) {
	s := &certcloset.FailureState{LastFailure: map[string]string{
		"x.com": time.Now().Format(time.RFC3339),
	}}
	if !testApp.isInBackoff(s, "x.com", 60) {
		t.Fatal("recent failure must return true")
	}
}

func TestIsInBackoffExpiredFailure(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	s := &certcloset.FailureState{LastFailure: map[string]string{"x.com": old}}
	if testApp.isInBackoff(s, "x.com", 60) {
		t.Fatal("old failure (2h) with 60m backoff must return false")
	}
}

func TestIsInBackoffBadTimestamp(t *testing.T) {
	s := &certcloset.FailureState{LastFailure: map[string]string{"x.com": "not-a-time"}}
	if testApp.isInBackoff(s, "x.com", 60) {
		t.Fatal("unparseable timestamp must return false (safe default)")
	}
}

func TestRecordFailure(t *testing.T) {
	s := &certcloset.FailureState{LastFailure: make(map[string]string)}
	testApp.recordFailure(s, "x.com")
	if _, ok := s.LastFailure["x.com"]; !ok {
		t.Fatal("failure not recorded")
	}
	tStr := s.LastFailure["x.com"]
	if _, err := time.Parse(time.RFC3339, tStr); err != nil {
		t.Errorf("recorded timestamp not RFC3339: %q", tStr)
	}
}

func TestRecordFailureNilState(t *testing.T) {
	testApp.recordFailure(nil, "x.com") // must not panic
}

func TestClearFailure(t *testing.T) {
	s := &certcloset.FailureState{LastFailure: map[string]string{"x.com": time.Now().Format(time.RFC3339)}}
	testApp.clearFailure(s, "x.com")
	if _, ok := s.LastFailure["x.com"]; ok {
		t.Fatal("failure not cleared")
	}
}

func TestClearFailureNilState(t *testing.T) {
	testApp.clearFailure(nil, "x.com") // must not panic
}

func TestLoadFailureStateNilStore(t *testing.T) {
	a := &App{} // state is nil
	s, err := a.loadFailureState()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.LastFailure == nil {
		t.Fatal("LastFailure map must not be nil")
	}
}

func TestGetDomainsWithRetrySuccess(t *testing.T) {
	a := &App{}
	calls := 0
	a.traefikApi = &mockDomainProvider{fn: func() ([]string, error) {
		calls++
		return []string{"ok.com"}, nil
	}}
	domains, err := a.getDomainsWithRetry(3, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 1 || domains[0] != "ok.com" {
		t.Errorf("unexpected domains: %v", domains)
	}
	if calls != 1 {
		t.Errorf("want 1 call got %d", calls)
	}
}

func TestGetDomainsWithRetryExhausted(t *testing.T) {
	a := &App{}
	a.traefikApi = &mockDomainProvider{fn: func() ([]string, error) {
		return nil, fmt.Errorf("traefik down")
	}}
	_, err := a.getDomainsWithRetry(3, 0)
	if err == nil {
		t.Fatal("expected error after all retries exhausted")
	}
}

func TestGetDomainsWithRetryEventualSuccess(t *testing.T) {
	a := &App{}
	calls := 0
	a.traefikApi = &mockDomainProvider{fn: func() ([]string, error) {
		calls++
		if calls < 3 {
			return nil, fmt.Errorf("not yet")
		}
		return []string{"eventual.com"}, nil
	}}
	domains, err := a.getDomainsWithRetry(3, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) == 0 {
		t.Fatal("expected domains on eventual success")
	}
}

// mockDomainProvider satisfies domainProvider.
type mockDomainProvider struct {
	fn func() ([]string, error)
}

func (m *mockDomainProvider) GetDomains() ([]string, error) { return m.fn() }
