package app

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
)

// ---------- cert store mock ----------

type mockStore struct {
	index          certcloset.CertificateList
	saveIndexErr   error
	saveIndexCalls int
	storeErr       error
	stored         []certificate.Resource
	existsMap      map[string]bool
	existsErr      error
	retrieveMap    map[string]*certcloset.Certificate
	retrieveErr    error
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
func (m *mockStore) RemoveFromIndex(domain string) { m.index.Remove(domain) }
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

// ---------- state store mock ----------

type mockStateStore struct {
	failureState  *certcloset.FailureState
	rolloverState map[string]*certcloset.RolloverState
	pendingKeys   map[string][]byte
	loadFSErr     error
	storeFSErr    error
}

func newMockStateStore() *mockStateStore {
	return &mockStateStore{
		failureState:  &certcloset.FailureState{LastFailure: make(map[string]string)},
		rolloverState: make(map[string]*certcloset.RolloverState),
		pendingKeys:   make(map[string][]byte),
	}
}

func (m *mockStateStore) AcquireLock() error { return nil }
func (m *mockStateStore) RefreshLock() error { return nil }
func (m *mockStateStore) ReleaseLock()       {}

func (m *mockStateStore) LoadFailureState() (*certcloset.FailureState, error) {
	return m.failureState, m.loadFSErr
}
func (m *mockStateStore) StoreFailureState(s *certcloset.FailureState) error {
	if m.storeFSErr == nil {
		m.failureState = s
	}
	return m.storeFSErr
}
func (m *mockStateStore) LoadRolloverState(domain string) (*certcloset.RolloverState, bool, error) {
	s, ok := m.rolloverState[domain]
	return s, ok, nil
}
func (m *mockStateStore) StoreRolloverState(domain string, s *certcloset.RolloverState) error {
	m.rolloverState[domain] = s
	return nil
}
func (m *mockStateStore) DeleteRolloverState(domain string) error {
	delete(m.rolloverState, domain)
	return nil
}
func (m *mockStateStore) StorePendingKey(domain string, keyPEM []byte) error {
	m.pendingKeys[domain] = keyPEM
	return nil
}
func (m *mockStateStore) LoadPendingKey(domain string) ([]byte, error) {
	k, ok := m.pendingKeys[domain]
	if !ok {
		return nil, fmt.Errorf("no pending key for %s", domain)
	}
	return k, nil
}
func (m *mockStateStore) DeletePendingKey(domain string) error {
	delete(m.pendingKeys, domain)
	return nil
}

// ---------- cert requester mock ----------

type mockRequester struct {
	cert  *certificate.Resource
	err   error
	calls int
	// for RequestCertWithKey
	certWithKey  *certificate.Resource
	errWithKey   error
	callsWithKey int
}

func (m *mockRequester) RequestCert(_ []string) (*certificate.Resource, error) {
	m.calls++
	return m.cert, m.err
}

func (m *mockRequester) RequestCertWithKey(_ []string, _ []byte) (*certificate.Resource, error) {
	m.callsWithKey++
	if m.certWithKey != nil {
		return m.certWithKey, m.errWithKey
	}
	return m.cert, m.errWithKey
}

// ---------- DNS updater mock ----------

type mockDNSUpdater struct {
	calls          []string // domains UpdateDNS was called with
	err            error
	enabledFn      func(domain string) bool
	addTLSACalls   []string
	remTLSACalls   []string
	updateCAACalls []string
}

func (m *mockDNSUpdater) UpdateDNS(domain string, _ []byte) error {
	m.calls = append(m.calls, domain)
	return m.err
}
func (m *mockDNSUpdater) AddTLSA(domain, _ string) error {
	m.addTLSACalls = append(m.addTLSACalls, domain)
	return nil
}
func (m *mockDNSUpdater) RemoveTLSA(domain, _ string) error {
	m.remTLSACalls = append(m.remTLSACalls, domain)
	return nil
}
func (m *mockDNSUpdater) UpdateCAA(domain string) error {
	m.updateCAACalls = append(m.updateCAACalls, domain)
	return nil
}
func (m *mockDNSUpdater) Enabled(domain string) bool {
	if m.enabledFn != nil {
		return m.enabledFn(domain)
	}
	return false // default: rollover not triggered
}

// ---------- helpers ----------

func renewCfg() RenewConfig {
	return RenewConfig{
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

// ---------- basic renewal tests ----------

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
	store.index.CertIndex["valid.com"] = certcloset.CertificateEntry{
		Domain:         "valid.com",
		ExpirationDate: time.Now().AddDate(1, 0, 0),
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
	store.existsMap["stale.com"] = false

	req := &mockRequester{cert: fakeCert("stale.com")}
	a := &App{closet: store, buckcert: req}

	a.renew(renewCfg(), []string{"stale.com"})

	if req.calls != 1 {
		t.Fatalf("cert missing in S3 must be re-requested, got %d request(s)", req.calls)
	}
}

func TestRenewExpiredCert(t *testing.T) {
	store := newMockStore()
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
	st := newMockStateStore()
	st.failureState.LastFailure["backoff.com"] = time.Now().Format(time.RFC3339)

	req := &mockRequester{cert: fakeCert("backoff.com")}
	a := &App{
		closet:   newMockStore(),
		buckcert: req,
		state:    st,
	}

	cfg := renewCfg()
	cfg.FailureBackoffMinutes = 60

	a.renew(cfg, []string{"backoff.com"})

	if req.calls != 0 {
		t.Fatalf("domain in backoff must be skipped, got %d request(s)", req.calls)
	}
}

func TestRenewDomainInBackoffForced(t *testing.T) {
	st := newMockStateStore()
	st.failureState.LastFailure["backoff.com"] = time.Now().Format(time.RFC3339)

	req := &mockRequester{cert: fakeCert("backoff.com")}
	a := &App{
		closet:   newMockStore(),
		buckcert: req,
		state:    st,
	}

	cfg := renewCfg()
	cfg.FailureBackoffMinutes = 60
	cfg.ForceRenewOnFailure = true

	a.renew(cfg, []string{"backoff.com"})

	if req.calls != 1 {
		t.Fatalf("forced renew must bypass backoff, got %d request(s)", req.calls)
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

func (p *partialRequester) RequestCertWithKey(domains []string, _ []byte) (*certificate.Resource, error) {
	return p.RequestCert(domains)
}

// ---------- DNS updater tests ----------

func TestRenewCallsDNSUpdater(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("dns.com")}
	updater := &mockDNSUpdater{}
	a := &App{closet: store, buckcert: req, dnsUpdate: updater}

	a.renew(renewCfg(), []string{"dns.com"})

	if len(updater.calls) != 1 || updater.calls[0] != "dns.com" {
		t.Fatalf("DNS updater must be called once with domain, got %v", updater.calls)
	}
}

func TestRenewDNSUpdaterFailureNonFatal(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("dns.com")}
	updater := &mockDNSUpdater{err: fmt.Errorf("DNS error")}
	a := &App{closet: store, buckcert: req, dnsUpdate: updater}

	a.renew(renewCfg(), []string{"dns.com"})

	if len(store.stored) != 1 {
		t.Fatal("cert must be stored even when DNS update fails")
	}
	if store.saveIndexCalls == 0 {
		t.Fatal("index must be saved even when DNS update fails")
	}
}

// ---------- rollover tests ----------

func TestRenewStartsRolloverWhenEnabled(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("roll.com")}
	st := newMockStateStore()
	updater := &mockDNSUpdater{enabledFn: func(string) bool { return true }}

	cfg := renewCfg()
	cfg.DNSUpdate.RolloverEnabled = true
	cfg.DNSUpdate.TLSATTLSeconds = 3600

	a := &App{closet: store, buckcert: req, state: st, dnsUpdate: updater}
	a.renew(cfg, []string{"roll.com"})

	// Rollover started → no cert requested yet, TLSA pre-published.
	if req.calls != 0 {
		t.Fatalf("cert must not be requested during rollover start, got %d", req.calls)
	}
	if len(updater.addTLSACalls) != 1 {
		t.Fatalf("want 1 AddTLSA call got %d", len(updater.addTLSACalls))
	}
	if _, exists, _ := st.LoadRolloverState("roll.com"); !exists {
		t.Fatal("rollover state must be stored after start")
	}
}

func TestRenewPrePublishingPhaseWaitsForTTL(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("roll.com")}
	st := newMockStateStore()
	// Store rollover state with PhaseStartedAt = now (TTL not elapsed yet).
	_ = st.StoreRolloverState("roll.com", &certcloset.RolloverState{
		Phase:          certcloset.RolloverPhasePrePublishing,
		NewTLSAHex:     "aabbcc",
		PhaseStartedAt: time.Now(),
		TLSATTLSeconds: 3600,
		SyncLagSeconds: 300,
	})
	updater := &mockDNSUpdater{enabledFn: func(string) bool { return true }}

	a := &App{closet: store, buckcert: req, state: st, dnsUpdate: updater}
	a.renew(renewCfg(), []string{"roll.com"})

	if req.calls != 0 || req.callsWithKey != 0 {
		t.Fatalf("must not request cert while TTL waiting, calls=%d/%d", req.calls, req.callsWithKey)
	}
}

func TestRenewPrePublishingPhaseAdvancesAfterTTL(t *testing.T) {
	store := newMockStore()
	cert := fakeCert("roll.com")
	req := &mockRequester{cert: cert, certWithKey: cert}
	st := newMockStateStore()
	// Store pending key so LoadPendingKey succeeds.
	_ = st.StorePendingKey("roll.com", []byte("fake-key-pem"))
	// Store rollover state with PhaseStartedAt in the past (TTL elapsed).
	_ = st.StoreRolloverState("roll.com", &certcloset.RolloverState{
		Phase:          certcloset.RolloverPhasePrePublishing,
		NewTLSAHex:     "aabbcc",
		PhaseStartedAt: time.Now().Add(-2 * time.Hour),
		TLSATTLSeconds: 3600,
		SyncLagSeconds: 300,
	})
	updater := &mockDNSUpdater{enabledFn: func(string) bool { return true }}

	a := &App{closet: store, buckcert: req, state: st, dnsUpdate: updater}
	a.renew(renewCfg(), []string{"roll.com"})

	if req.callsWithKey != 1 {
		t.Fatalf("want 1 RequestCertWithKey call, got %d", req.callsWithKey)
	}
	if len(store.stored) != 1 {
		t.Fatalf("want cert stored after TTL elapsed, got %d", len(store.stored))
	}
	rs, exists, _ := st.LoadRolloverState("roll.com")
	if !exists {
		t.Fatal("rollover state must still exist in CertSwitched phase")
	}
	if rs.Phase != certcloset.RolloverPhaseCertSwitched {
		t.Fatalf("want CertSwitched phase, got %q", rs.Phase)
	}
}

func TestRenewCertSwitchedPhaseWaitsForSyncLag(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("roll.com")}
	st := newMockStateStore()
	_ = st.StoreRolloverState("roll.com", &certcloset.RolloverState{
		Phase:          certcloset.RolloverPhaseCertSwitched,
		OldTLSAHex:     "oldoldold",
		NewTLSAHex:     "newnewnew",
		PhaseStartedAt: time.Now(), // lag not elapsed
		SyncLagSeconds: 300,
	})
	updater := &mockDNSUpdater{enabledFn: func(string) bool { return true }}

	a := &App{closet: store, buckcert: req, state: st, dnsUpdate: updater}
	a.renew(renewCfg(), []string{"roll.com"})

	if len(updater.remTLSACalls) != 0 {
		t.Fatal("must not remove old TLSA while sync lag waiting")
	}
	if _, exists, _ := st.LoadRolloverState("roll.com"); !exists {
		t.Fatal("rollover state must persist while waiting")
	}
}

func TestRenewCertSwitchedPhaseCompletesAfterSyncLag(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("roll.com")}
	st := newMockStateStore()
	_ = st.StoreRolloverState("roll.com", &certcloset.RolloverState{
		Phase:          certcloset.RolloverPhaseCertSwitched,
		OldTLSAHex:     "oldoldold",
		NewTLSAHex:     "newnewnew",
		PhaseStartedAt: time.Now().Add(-10 * time.Minute), // lag elapsed
		SyncLagSeconds: 300,
	})
	updater := &mockDNSUpdater{enabledFn: func(string) bool { return true }}

	a := &App{closet: store, buckcert: req, state: st, dnsUpdate: updater}
	a.renew(renewCfg(), []string{"roll.com"})

	if len(updater.remTLSACalls) != 1 {
		t.Fatalf("want 1 RemoveTLSA call, got %d", len(updater.remTLSACalls))
	}
	if _, exists, _ := st.LoadRolloverState("roll.com"); exists {
		t.Fatal("rollover state must be deleted after completion")
	}
}

// ---------- public Renew() tests ----------

func TestRenewPublicNoDomainsAfterFilter(t *testing.T) {
	store := newMockStore()
	req := &mockRequester{cert: fakeCert("x.com")}
	a := &App{closet: store, buckcert: req}

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
		Traefik:               traefikclient.ApiConfig{Url: "http://traefik.local"},
	}
	a.Renew(cfg)

	if req.calls != 2 {
		t.Fatalf("want 2 requests (direct + traefik domain), got %d", req.calls)
	}
}

// ---------- App.Close ----------

func TestAppCloseNilWriter(t *testing.T) {
	a := &App{}
	a.Close() // must not panic
}
