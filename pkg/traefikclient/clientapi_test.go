package traefikclient

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewTraefikApiClientEmptyURL(t *testing.T) {
	_, err := NewTraefikApiClient(ApiConfig{Url: ""})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewTraefikApiClientStripTrailingSlash(t *testing.T) {
	c, err := NewTraefikApiClient(ApiConfig{Url: "http://traefik.local/", Timeout: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.apiConfig.Url != "http://traefik.local" {
		t.Errorf("trailing slash not stripped: %q", c.apiConfig.Url)
	}
}

func TestGetDomainsOK(t *testing.T) {
	routers := []TraefikRouter{
		{Rule: `Host("alpha.example.com")`},
		{Rule: `Host("beta.example.com")`},
		{Rule: `PathPrefix("/static")`}, // no domain, should be skipped
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(routers)
	}))
	defer ts.Close()

	c, err := NewTraefikApiClient(ApiConfig{Url: ts.URL, Timeout: 5})
	if err != nil {
		t.Fatalf("NewTraefikApiClient: %v", err)
	}
	domains, err := c.GetDomains()
	if err != nil {
		t.Fatalf("GetDomains: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("want 2 domains got %d: %v", len(domains), domains)
	}
}

func TestGetDomainsHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	c, err := NewTraefikApiClient(ApiConfig{Url: ts.URL, Timeout: 5})
	if err != nil {
		t.Fatalf("NewTraefikApiClient: %v", err)
	}
	_, err = c.GetDomains()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestGetDomainsInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json {{{"))
	}))
	defer ts.Close()

	c, err := NewTraefikApiClient(ApiConfig{Url: ts.URL, Timeout: 5})
	if err != nil {
		t.Fatalf("NewTraefikApiClient: %v", err)
	}
	_, err = c.GetDomains()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestGetDomainsBasicAuth(t *testing.T) {
	var gotUser, gotPass string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer ts.Close()

	c, err := NewTraefikApiClient(ApiConfig{
		Url:      ts.URL,
		Username: "admin",
		Password: "secret",
		Timeout:  5,
	})
	if err != nil {
		t.Fatalf("NewTraefikApiClient: %v", err)
	}
	if _, err := c.GetDomains(); err != nil {
		t.Fatalf("GetDomains: %v", err)
	}
	if gotUser != "admin" || gotPass != "secret" {
		t.Errorf("basic auth want admin/secret got %q/%q", gotUser, gotPass)
	}
}

func TestNewTraefikApiClientInsecureTLS(t *testing.T) {
	c, err := NewTraefikApiClient(ApiConfig{Url: "https://traefik.local", Insecure: true, Timeout: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must be true when Insecure=true")
	}
}

func TestNewTraefikApiClientSecureTLS(t *testing.T) {
	c, err := NewTraefikApiClient(ApiConfig{Url: "https://traefik.local", Insecure: false, Timeout: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	// TLSClientConfig may be nil (default secure) or have InsecureSkipVerify=false
	if transport.TLSClientConfig != nil {
		if transport.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify must be false when Insecure=false")
		}
	}
}

func TestGetDomainsInsecureTLSServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"rule":"Host(\"tls.com\")"}]`))
	}))
	defer ts.Close()

	c, err := NewTraefikApiClient(ApiConfig{Url: ts.URL, Insecure: true, Timeout: 5})
	if err != nil {
		t.Fatalf("NewTraefikApiClient: %v", err)
	}
	// Override with the test server's client to trust the cert
	c.httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	domains, err := c.GetDomains()
	if err != nil {
		t.Fatalf("GetDomains: %v", err)
	}
	if len(domains) != 1 || domains[0] != "tls.com" {
		t.Errorf("want [tls.com] got %v", domains)
	}
}

func TestGetDomainsEmptyList(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer ts.Close()

	c, err := NewTraefikApiClient(ApiConfig{Url: ts.URL, Timeout: 5})
	if err != nil {
		t.Fatalf("NewTraefikApiClient: %v", err)
	}
	domains, err := c.GetDomains()
	if err != nil {
		t.Fatalf("GetDomains: %v", err)
	}
	if len(domains) != 0 {
		t.Fatalf("want 0 domains got %d", len(domains))
	}
}
