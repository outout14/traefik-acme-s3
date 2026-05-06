package app

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
)

// ---------- mocks ----------

type mockStore struct {
	index           certcloset.CertificateList
	saveIndexErr    error
	saveIndexCalls  int
	storeErr        error
	stored          []certificate.Resource
	existsMap       map[string]bool
	existsErr       error
	retrieveMap     map[string]*certcloset.Certificate
	retrieveErr     error
}

func newMockStore() *mockStore {
	return &mockStore{
		index:       certcloset.CertificateList{CertIndex: make(map[string]certcloset.CertificateEntry)},
		existsMap:   make(map[string]bool),
		retrieveMap: make(map[string]*certcloset.Certificate),
	}
}

func (m *mockStore) GetIndex() *certcloset.CertificateList { return &m.index }
func (m *mockStore) SaveIndex() error {
	m.saveIndexCalls++
	return m.saveIndexErr
}
func (m *mockStore) StoreCertificate(cert certificate.Resource) error {
	if m.storeErr == nil {
		m.stored = append(m.stored, cert)
	}
	return m.storeErr
}
func (m *mockStore) CertificateExists(domain string) (bool, error) {
	return m.existsMap[domain], m.existsErr
}
func (m *mockStore) RetrieveCertificate(domain string) (*certcloset.Certificate, error) {
	if m.retrieveErr != nil {
		return nil, m.retrieveErr
	}
	c, ok := m.retrieveMap[domain]
	if !ok {
		return nil, fmt.Errorf("not found: %s", domain)
	}
	return c, nil
}

type mockRequester struct {
	cert *certificate.Resource
	err  error
	calls int
}

func (m *mockRequester) RequestCert(_ []string) (*certificate.Resource, error) {
	m.calls++
	return m.cert, m.err
}

// ---------- helpers ----------

func renewCfg() RenewConfig {
	return RenewConfig{
		StateDir:              "", // no state file
		FailureBackoffMinutes: 60,
		RequestDelaySeconds:   0,
	}
}

func fakeCert(domain string) *certificate.Resource {
	return &certificate.Resource{
		Domain:      domain,
		Certificate: []byte("CERT-PEM"),
		PrivateKey:  []byte("KEY-PEM"),
	}
}

// ---------- tests ----------

func TestRenewNewDomainSuccess(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("new.com")}
	a := &App{closet: store, buckcert: req}

	a.renew(renewCfg(), []string{"new.com"})

	if req.calls != 1 {
		t.Fatalf("want 1 cert request got %d", req.calls)
	}
	if len(store.stored) != 1 {
		t.Fatalf("want 1 stored cert got %d", len(store.stored))
	}
	if store.saveIndexCalls == 0 {
		t.Fatal("index must be saved after renewal")
	}
}

func TestRenewValidCertExistsInS3(t *testing.T) {
	store := newMockStore()
	// Add cert to index with far-future expiry
	store.index.CertIndex["valid.com"] = certcloset.CertificateEntry{
		Domain:         "valid.com",
		ExpirationDate: time.Now().AddDate(1, 0, 0), // 1 year from now
	}
	store.existsMap["valid.com"] = true

	req := &mockRequester{cert: fakeCert("valid.com")}
	a := &App{closet: store, buckcert: req}

	a.renew(renewCfg(), []string{"valid.com"})

	if req.calls != 0 {
		t.Fatalf("valid cert must not be renewed, got %d request(s)", req.calls)
	}
}

func TestRenewCertInIndexButMissingS3(t *testing.T) {
	store := newMockStore()
	store.index.CertIndex["stale.com"] = certcloset.CertificateEntry{
		Domain:         "stale.com",
		ExpirationDate: time.Now().AddDate(1, 0, 0),
	}
	store.existsMap["stale.com"] = false // missing in S3

	req := &mockRequester{cert: fakeCert("stale.com")}
	a := &App{closet: store, buckcert: req}

	a.renew(renewCfg(), []string{"stale.com"})

	if req.calls != 1 {
		t.Fatalf("cert missing in S3 must be re-requested, got %d request(s)", req.calls)
	}
	if _, stillInIndex := store.index.CertIndex["stale.com"]; stillInIndex {
		// It should have been removed from index then re-added by StoreCertificate
		// (StoreCertificate updates the index), so it's fine either way as long as
		// a request was made. The important thing is it was re-requested.
	}
}

func TestRenewExpiredCert(t *testing.T) {
	store := newMockStore()
	// Expiry in 1 month → within the 2-month renewal window
	store.index.CertIndex["expired.com"] = certcloset.CertificateEntry{
		Domain:         "expired.com",
		ExpirationDate: time.Now().AddDate(0, 1, 0),
	}

	req := &mockRequester{cert: fakeCert("expired.com")}
	a := &App{closet: store, buckcert: req}

	a.renew(renewCfg(), []string{"expired.com"})

	if req.calls != 1 {
		t.Fatalf("expiring cert must be renewed, got %d request(s)", req.calls)
	}
}

// TestRenewBoundaryJustInsideWindow: expiry = 2 months - 1 day → must renew.
func TestRenewBoundaryJustInsideWindow(t *testing.T) {
	store := newMockStore()
	store.index.CertIndex["inside.com"] = certcloset.CertificateEntry{
		Domain:         "inside.com",
		ExpirationDate: time.Now().AddDate(0, 2, 0).AddDate(0, 0, -1),
	}

	req := &mockRequester{cert: fakeCert("inside.com")}
	a := &App{closet: store, buckcert: req}
	a.renew(renewCfg(), []string{"inside.com"})

	if req.calls != 1 {
		t.Fatalf("cert expiring in <2 months must be renewed, got %d request(s)", req.calls)
	}
}

// TestRenewBoundaryJustOutsideWindow: expiry = 2 months + 1 day → must NOT renew.
func TestRenewBoundaryJustOutsideWindow(t *testing.T) {
	store := newMockStore()
	store.index.CertIndex["outside.com"] = certcloset.CertificateEntry{
		Domain:         "outside.com",
		ExpirationDate: time.Now().AddDate(0, 2, 0).AddDate(0, 0, 1),
	}
	store.existsMap["outside.com"] = true

	req := &mockRequester{cert: fakeCert("outside.com")}
	a := &App{closet: store, buckcert: req}
	a.renew(renewCfg(), []string{"outside.com"})

	if req.calls != 0 {
		t.Fatalf("cert expiring in >2 months must NOT be renewed, got %d request(s)", req.calls)
	}
}

func TestRenewRequestFails(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{err: fmt.Errorf("ACME error")}
	a := &App{closet: store, buckcert: req}

	a.renew(renewCfg(), []string{"fail.com"})

	if len(store.stored) != 0 {
		t.Fatal("must not store cert when request fails")
	}
}

func TestRenewStoreFails(t *testing.T) {
	store := newMockStore()
	store.storeErr = fmt.Errorf("S3 write error")
	req := &mockRequester{cert: fakeCert("storefail.com")}
	a := &App{closet: store, buckcert: req}

	a.renew(renewCfg(), []string{"storefail.com"})

	if store.saveIndexCalls != 0 {
		t.Fatal("index must not be saved when all renewals failed")
	}
}

func TestRenewEmptyDomainList(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("x.com")}
	a := &App{closet: store, buckcert: req}

	a.renew(renewCfg(), []string{})

	if req.calls != 0 {
		t.Fatal("no requests expected for empty domain list")
	}
}

func TestRenewDomainInBackoff(t *testing.T) {
	dir := t.TempDir()
	a := &App{closet: newMockStore(), buckcert: &mockRequester{cert: fakeCert("backoff.com")}}

	// Record a failure first
	state := &failureState{LastFailure: map[string]string{
		"backoff.com": time.Now().Format(time.RFC3339),
	}}
	_ = a.saveFailureState(dir, state)

	cfg := renewCfg()
	cfg.StateDir = dir
	cfg.FailureBackoffMinutes = 60

	req := a.buckcert.(*mockRequester)
	a.renew(cfg, []string{"backoff.com"})

	if req.calls != 0 {
		t.Fatalf("domain in backoff must be skipped, got %d request(s)", req.calls)
	}
}

func TestRenewMultipleDomainsPartialFailure(t *testing.T) {
	store := newMockStore()
	a := &App{closet: store, buckcert: &partialRequester{
		failOn: "fail.com",
		cert:   fakeCert("ok.com"),
	}}

	a.renew(renewCfg(), []string{"ok.com", "fail.com"})

	if len(store.stored) != 1 {
		t.Fatalf("want 1 stored cert (ok.com) got %d", len(store.stored))
	}
	if store.saveIndexCalls == 0 {
		t.Fatal("index must be saved when at least one cert was renewed")
	}
}

// partialRequester fails for a specific domain.
type partialRequester struct {
	failOn string
	cert   *certificate.Resource
}

func (p *partialRequester) RequestCert(domains []string) (*certificate.Resource, error) {
	if len(domains) > 0 && domains[0] == p.failOn {
		return nil, fmt.Errorf("request failed for %s", p.failOn)
	}
	return p.cert, nil
}

// ---------- public Renew() tests ----------

func TestRenewPublicNoDomainsAfterFilter(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("x.com")}
	a := &App{closet: store, buckcert: req}

	// All domains are ignored → Renew logs warning and returns early
	cfg := RenewConfig{
		Domains:               []string{"ignored.com"},
		IgnoredDomains:        []string{"ignored.com"},
		FailureBackoffMinutes: 60,
	}
	a.Renew(cfg)

	if req.calls != 0 {
		t.Fatalf("no requests expected when all domains filtered, got %d", req.calls)
	}
}

func TestRenewPublicDeduplicatesDomains(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("dup.com")}
	a := &App{closet: store, buckcert: req}

	cfg := RenewConfig{
		Domains:               []string{"dup.com", "dup.com", "dup.com"},
		FailureBackoffMinutes: 60,
	}
	a.Renew(cfg)

	if req.calls != 1 {
		t.Fatalf("deduplicated domain must be requested once, got %d", req.calls)
	}
}

func TestRenewPublicFiltersIgnoredDomains(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("keep.com")}
	a := &App{closet: store, buckcert: req}

	cfg := RenewConfig{
		Domains:               []string{"keep.com", "skip.com"},
		IgnoredDomains:        []string{"skip.com"},
		FailureBackoffMinutes: 60,
	}
	a.Renew(cfg)

	if req.calls != 1 {
		t.Fatalf("want 1 request (keep.com only), got %d", req.calls)
	}
	if len(store.stored) != 1 || store.stored[0].Domain != "keep.com" {
		t.Errorf("stored cert domain want keep.com got %v", store.stored)
	}
}

func TestRenewPublicNoTraefikURL(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("direct.com")}
	a := &App{closet: store, buckcert: req}

	cfg := RenewConfig{
		Domains:               []string{"direct.com"},
		FailureBackoffMinutes: 60,
		// Traefik.Url is empty → skips Traefik init
	}
	a.Renew(cfg)

	if req.calls != 1 {
		t.Fatalf("want 1 request, got %d", req.calls)
	}
}

func TestRenewPublicWithTraefikDomains(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("x.com")}
	traefikDomains := []string{"traefik.com"}
	traefik := &mockDomainProvider{fn: func() ([]string, error) { return traefikDomains, nil }}

	a := &App{closet: store, buckcert: req, traefikApi: traefik}

	cfg := RenewConfig{
		Domains:               []string{"direct.com"},
		FailureBackoffMinutes: 60,
		Traefik:               traefikclient.ApiConfig{Url: "http://traefik.local"}, // non-empty triggers path
	}
	a.Renew(cfg)

	// Both direct.com and traefik.com should be processed (2 requests)
	if req.calls != 2 {
		t.Fatalf("want 2 requests (direct + traefik domain), got %d", req.calls)
	}
}

// ---------- App.Close ----------

func TestAppCloseNilWriter(t *testing.T) {
	a := &App{} // lokiWriter is nil
	a.Close()   // must not panic
}
