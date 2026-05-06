package app

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestWriteCertificate(t *testing.T) {
	dir := t.TempDir()
	a := &App{}
	cert := &certcloset.Certificate{
		Domain:      "write.com",
		Certificate: []byte("CERT-PEM-DATA"),
		PrivateKey:  []byte("KEY-PEM-DATA"),
	}
	if err := a.writeCertificate(dir, cert); err != nil {
		t.Fatalf("writeCertificate: %v", err)
	}

	certPath := filepath.Join(dir, "write.com", CERT_EXT)
	keyPath := filepath.Join(dir, "write.com", KEY_EXT)

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(certData) != "CERT-PEM-DATA" {
		t.Errorf("cert content mismatch: %q", certData)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(keyData) != "KEY-PEM-DATA" {
		t.Errorf("key content mismatch: %q", keyData)
	}
}

func TestWriteTraefikConfigTOML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "traefik.toml")

	store := newMockStore()
	store.index.CertIndex["toml.com"] = certcloset.CertificateEntry{Domain: "toml.com"}

	a := &App{closet: store}
	cfg := SyncConfig{}
	cfg.Traefik.ConfigFile = cfgFile
	cfg.Traefik.Format = "toml"
	cfg.Traefik.CertificateDir = "/certs"

	if err := a.writeTraefikConfig(cfg); err != nil {
		t.Fatalf("writeTraefikConfig: %v", err)
	}

	data, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "toml.com") {
		t.Errorf("config does not reference toml.com:\n%s", content)
	}
	if !strings.Contains(content, "certFile") {
		t.Errorf("config missing certFile:\n%s", content)
	}
}

func TestWriteTraefikConfigYAML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "traefik.yaml")

	store := newMockStore()
	store.index.CertIndex["yaml.com"] = certcloset.CertificateEntry{Domain: "yaml.com"}

	a := &App{closet: store}
	cfg := SyncConfig{}
	cfg.Traefik.ConfigFile = cfgFile
	cfg.Traefik.Format = "yaml"
	cfg.Traefik.CertificateDir = "/certs"

	if err := a.writeTraefikConfig(cfg); err != nil {
		t.Fatalf("writeTraefikConfig: %v", err)
	}

	data, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "yaml.com") {
		t.Errorf("config does not reference yaml.com:\n%s", content)
	}
}

func TestWriteTraefikConfigUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	store := newMockStore()
	a := &App{closet: store}
	cfg := SyncConfig{}
	cfg.Traefik.ConfigFile = filepath.Join(dir, "traefik.xml")
	cfg.Traefik.Format = "xml"

	if err := a.writeTraefikConfig(cfg); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestSyncCertsNoDiff(t *testing.T) {
	localDir := t.TempDir()

	exp := time.Now().AddDate(1, 0, 0)
	store := newMockStore()
	store.index.CertIndex["nodiff.com"] = certcloset.CertificateEntry{
		Domain: "nodiff.com", ExpirationDate: exp,
	}

	a := &App{closet: store, config: Config{}}

	cfg := SyncConfig{}
	cfg.Traefik.LocalStore = localDir

	// Pre-populate local index with same entry so diff is empty.
	// Also create the cert directory so CheckIntegrity does not flag it.
	if err := os.MkdirAll(filepath.Join(localDir, "nodiff.com"), 0755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	lc, err := certcloset.NewLocalCertCloset(certcloset.Config{}, localDir)
	if err != nil {
		t.Fatalf("NewLocalCertCloset: %v", err)
	}
	lc.GetIndex().Add(certcloset.CertificateEntry{Domain: "nodiff.com", ExpirationDate: exp})
	if err := lc.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	retrieveCalled := false
	customStore := &mockStoreWithRetrieve{
		mockStore: *store,
		retrieveFn: func(domain string) (*certcloset.Certificate, error) {
			retrieveCalled = true
			return nil, fmt.Errorf("should not be called")
		},
	}

	a.closet = customStore
	if err := a.syncCerts(cfg); err != nil {
		t.Fatalf("syncCerts: %v", err)
	}
	if retrieveCalled {
		t.Fatal("RetrieveCertificate must not be called when remote and local indexes match")
	}
}

func TestSyncCertsDownloadsMissing(t *testing.T) {
	localDir := t.TempDir()

	exp := time.Now().AddDate(1, 0, 0)
	store := newMockStore()
	store.index.CertIndex["sync.com"] = certcloset.CertificateEntry{
		Domain: "sync.com", ExpirationDate: exp,
	}
	store.retrieveMap["sync.com"] = &certcloset.Certificate{
		Domain:      "sync.com",
		Certificate: []byte("SYNCED-CERT"),
		PrivateKey:  []byte("SYNCED-KEY"),
	}

	a := &App{closet: store, config: Config{}}

	cfg := SyncConfig{}
	cfg.Traefik.LocalStore = localDir

	// Local index is empty → diff will include sync.com
	if err := a.syncCerts(cfg); err != nil {
		t.Fatalf("syncCerts: %v", err)
	}

	certPath := filepath.Join(localDir, "sync.com", CERT_EXT)
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("cert file not written: %v", err)
	}
	if string(data) != "SYNCED-CERT" {
		t.Errorf("cert content mismatch: %q", data)
	}
}

func TestSyncCertsStaleS3Entry(t *testing.T) {
	localDir := t.TempDir()

	exp := time.Now().AddDate(1, 0, 0)
	store := newMockStore()
	store.index.CertIndex["stale-s3.com"] = certcloset.CertificateEntry{
		Domain: "stale-s3.com", ExpirationDate: exp,
	}
	// Retrieve returns not-found for this domain
	store.retrieveErr = nil
	// Override retrieve to return an error that IsErrNotFound recognizes
	// We use a custom mock for this case
	customStore := &staleS3Store{mockStore: *store}

	a := &App{closet: customStore, config: Config{}}
	cfg := SyncConfig{}
	cfg.Traefik.LocalStore = localDir

	if err := a.syncCerts(cfg); err != nil {
		t.Fatalf("syncCerts: %v", err)
	}
	// stale-s3.com should have been removed from index
	if _, ok := customStore.index.CertIndex["stale-s3.com"]; ok {
		t.Fatal("stale index entry must be removed when cert not in S3")
	}
}

// syncNotFoundErr constructs the error type that certcloset.IsErrNotFound recognises.
func syncNotFoundErr() error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{
				Response: &http.Response{StatusCode: http.StatusNotFound},
			},
		},
	}
}

// staleS3Store returns an IsErrNotFound-compatible error for RetrieveCertificate.
type staleS3Store struct {
	mockStore
}

func (s *staleS3Store) RetrieveCertificate(_ string) (*certcloset.Certificate, error) {
	return nil, syncNotFoundErr()
}

// Ensure mockStore satisfies certStore (compile-time check).
var _ certStore = (*mockStore)(nil)
var _ certRequester = (*mockRequester)(nil)

// mockStoreCertRetrieve wraps mockStore and allows injecting RetrieveCertificate behaviour
// without the staleS3Store complication.
type mockStoreWithRetrieve struct {
	mockStore
	retrieveFn func(string) (*certcloset.Certificate, error)
}

func (m *mockStoreWithRetrieve) RetrieveCertificate(domain string) (*certcloset.Certificate, error) {
	if m.retrieveFn != nil {
		return m.retrieveFn(domain)
	}
	return m.mockStore.RetrieveCertificate(domain)
}

func TestSyncCertsRetrieveError(t *testing.T) {
	localDir := t.TempDir()
	exp := time.Now().AddDate(1, 0, 0)

	store := &mockStoreWithRetrieve{
		mockStore: *newMockStore(),
		retrieveFn: func(domain string) (*certcloset.Certificate, error) {
			return nil, fmt.Errorf("S3 unavailable")
		},
	}
	store.index.CertIndex["err.com"] = certcloset.CertificateEntry{
		Domain: "err.com", ExpirationDate: exp,
	}

	a := &App{closet: store, config: Config{}}
	cfg := SyncConfig{}
	cfg.Traefik.LocalStore = localDir

	// syncCerts should not return an error for a per-cert retrieve failure
	if err := a.syncCerts(cfg); err != nil {
		t.Fatalf("syncCerts: %v", err)
	}
}

// Ensure mockStoreWithRetrieve satisfies certStore.
var _ certStore = (*mockStoreWithRetrieve)(nil)

// Verify StoreCertificate is still correctly delegated.
func (m *mockStoreWithRetrieve) StoreCertificate(cert certificate.Resource) error {
	return m.mockStore.StoreCertificate(cert)
}
