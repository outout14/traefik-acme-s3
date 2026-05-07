package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// ---------- DaemonConfig.Validate ----------

func TestDaemonConfigValidateZeroInterval(t *testing.T) {
	d := DaemonConfig{Interval: 0}
	if err := d.Validate(); err == nil {
		t.Fatal("zero interval must fail validation")
	}
}

func TestDaemonConfigValidateNegativeInterval(t *testing.T) {
	d := DaemonConfig{Interval: -1 * time.Second}
	if err := d.Validate(); err == nil {
		t.Fatal("negative interval must fail validation")
	}
}

func TestDaemonConfigValidatePositiveInterval(t *testing.T) {
	d := DaemonConfig{Interval: time.Hour}
	if err := d.Validate(); err != nil {
		t.Fatalf("positive interval must pass: %v", err)
	}
}

func TestDaemonConfigValidateHTTPAddrWithPositiveInterval(t *testing.T) {
	d := DaemonConfig{Interval: 5 * time.Minute, HTTPAddr: ":8080"}
	if err := d.Validate(); err != nil {
		t.Fatalf("HTTPAddr + positive interval must pass: %v", err)
	}
}

// ---------- resolveToken ----------

func TestResolveTokenFromEnv(t *testing.T) {
	tok, err := resolveToken("mytoken", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "mytoken" {
		t.Errorf("want mytoken got %q", tok)
	}
}

func TestResolveTokenFromFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte("  filetoken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tok, err := resolveToken("", f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "filetoken" {
		t.Errorf("want filetoken (trimmed) got %q", tok)
	}
}

func TestResolveTokenEnvTakesPriority(t *testing.T) {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte("filetoken"), 0600); err != nil {
		t.Fatal(err)
	}
	tok, err := resolveToken("envtoken", f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "envtoken" {
		t.Errorf("env token must win over file, got %q", tok)
	}
}

func TestResolveTokenNeitherSet(t *testing.T) {
	tok, err := resolveToken("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "" {
		t.Errorf("want empty token got %q", tok)
	}
}

func TestResolveTokenMissingFile(t *testing.T) {
	_, err := resolveToken("", "/no/such/file")
	if err == nil {
		t.Fatal("missing token file must return error")
	}
}

// ---------- authMiddleware ----------

func TestAuthMiddlewareNoToken(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authMiddleware("", inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("handler must be called when no token is configured")
	}
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authMiddleware("secret", inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("handler must be called with valid token")
	}
}

func TestAuthMiddlewareInvalidToken(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authMiddleware("secret", inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if called {
		t.Fatal("handler must NOT be called with invalid token")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401 got %d", rr.Code)
	}
}

func TestAuthMiddlewareMissingHeader(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := authMiddleware("secret", inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if called {
		t.Fatal("handler must NOT be called with missing auth header")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401 got %d", rr.Code)
	}
}

// ---------- rateLimitMiddleware ----------

func TestRateLimitMiddlewareNilLimiter(t *testing.T) {
	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ })
	h := rateLimitMiddleware(nil, inner)

	for i := 0; i < 20; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))
	}
	if calls != 20 {
		t.Fatalf("nil limiter must not restrict; want 20 calls got %d", calls)
	}
}

func TestRateLimitMiddlewareAllows(t *testing.T) {
	// burst=5, high rate so first 5 requests pass immediately
	limiter := rate.NewLimiter(rate.Every(time.Millisecond), 5)
	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ })
	h := rateLimitMiddleware(limiter, inner)

	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: want 200 got %d", i, rr.Code)
		}
	}
	if calls != 5 {
		t.Fatalf("want 5 calls got %d", calls)
	}
}

func TestRateLimitMiddlewareRejects(t *testing.T) {
	// burst=1, very slow refill — second request must be rejected
	limiter := rate.NewLimiter(rate.Every(time.Hour), 1)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := rateLimitMiddleware(limiter, inner)

	// first request consumes the token
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("first request: want 200 got %d", rr.Code)
	}

	// second request must be rate-limited
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/", nil))
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: want 429 got %d", rr2.Code)
	}
}

// ---------- isLoopback ----------

func TestIsLoopbackLocalhost(t *testing.T) {
	if !isLoopback("localhost:8080") {
		t.Fatal("localhost must be loopback")
	}
}

func TestIsLoopback127(t *testing.T) {
	if !isLoopback("127.0.0.1:8080") {
		t.Fatal("127.0.0.1 must be loopback")
	}
}

func TestIsLoopbackIPv6Loopback(t *testing.T) {
	if !isLoopback("[::1]:8080") {
		t.Fatal("::1 must be loopback")
	}
}

func TestIsLoopbackEmptyHost(t *testing.T) {
	// ":8080" means bind all interfaces — not loopback-only
	if isLoopback(":8080") {
		t.Fatal(":8080 (all interfaces) must NOT be loopback")
	}
}

func TestIsLoopbackPublicIP(t *testing.T) {
	if isLoopback("0.0.0.0:8080") {
		t.Fatal("0.0.0.0 must NOT be loopback")
	}
}

func TestIsLoopbackPublicDomain(t *testing.T) {
	if isLoopback("example.com:8080") {
		t.Fatal("public domain must NOT be loopback")
	}
}

func TestIsLoopbackMalformed(t *testing.T) {
	if isLoopback("not-an-address") {
		t.Fatal("malformed addr must NOT be loopback")
	}
}
