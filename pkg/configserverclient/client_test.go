package configserverclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func serveJSON(t *testing.T, path string, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
}

func TestGetDomainsAllBackends(t *testing.T) {
	srv := serveJSON(t, "/api/v1/backends", []map[string]any{
		{"id": 1, "fqdn": "a.com", "url": "http://a"},
		{"id": 2, "fqdn": "b.com", "url": "http://b"},
	})
	defer srv.Close()

	c, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	domains, err := c.GetDomains()
	if err != nil {
		t.Fatalf("GetDomains: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d: %v", len(domains), domains)
	}
}

func TestGetDomainsNodeFilter(t *testing.T) {
	srv := serveJSON(t, "/api/v1/nodes/lb-par01/backends", []map[string]any{
		{"id": 3, "fqdn": "c.com", "url": "http://c"},
	})
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Node: "lb-par01"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	domains, err := c.GetDomains()
	if err != nil {
		t.Fatalf("GetDomains: %v", err)
	}
	if len(domains) != 1 || domains[0] != "c.com" {
		t.Fatalf("unexpected domains: %v", domains)
	}
}

func TestGetDomainsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.GetDomains(); err == nil {
		t.Fatal("expected error for HTTP 404")
	}
}

func TestNewEmptyURL(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestGetDomainsSendsBearerToken(t *testing.T) {
	const token = "super-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("unexpected auth header: %q", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": 1, "fqdn": "a.com", "url": "http://a"},
		})
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Token: token})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.GetDomains(); err != nil {
		t.Fatalf("GetDomains: %v", err)
	}
}
