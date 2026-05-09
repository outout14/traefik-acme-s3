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
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
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

	keyStat, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyStat.Mode().Perm() != 0600 {
		t.Fatalf("key mode want 0600 got %o", keyStat.Mode().Perm())
	}
}

func TestWriteCertificateUnsafeDomain(t *testing.T) {
	dir := t.TempDir()
	a := &App{}
	cert := &certcloset.Certificate{
		Domain:      "../escape",
		Certificate: []byte("CERT"),
		PrivateKey:  []byte("KEY"),
	}
	if err := a.writeCertificate(dir, cert); err == nil {
		t.Fatal("expected error for unsafe domain")
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

func TestWriteTraefikConfigSkipsUnsafeDomain(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "traefik.toml")

	store := newMockStore()
	store.index.CertIndex["ok.com"] = certcloset.CertificateEntry{Domain: "ok.com"}
	store.index.CertIndex["../evil"] = certcloset.CertificateEntry{Domain: "../evil"}

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
	if !strings.Contains(content, "ok.com") {
		t.Fatalf("config missing safe domain: %s", content)
	}
	if strings.Contains(content, "../evil") {
		t.Fatalf("config must not include unsafe domain: %s", content)
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

func TestWriteTraefikConfigMissingCertificateDir(t *testing.T) {
	dir := t.TempDir()
	store := newMockStore()
	a := &App{closet: store}
	cfg := SyncConfig{}
	cfg.Traefik.ConfigFile = filepath.Join(dir, "traefik.toml")
	cfg.Traefik.Format = "toml"
	cfg.Traefik.CertificateDir = ""

	if err := a.writeTraefikConfig(cfg); err == nil {
		t.Fatal("expected error when certificate dir is empty and traefik output is enabled")
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
	// Also create the cert+key files so CheckIntegrity does not flag it.
	certDir := filepath.Join(localDir, "nodiff.com")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, CERT_EXT), []byte("CERT"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, KEY_EXT), []byte("KEY"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
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

	if err := a.syncCerts(cfg); err == nil {
		t.Fatal("syncCerts must fail when a certificate cannot be retrieved")
	}
}

func TestSyncCertsWriteFailureDoesNotAdvanceLocalIndex(t *testing.T) {
	localDir := t.TempDir()
	exp := time.Now().AddDate(1, 0, 0)

	store := newMockStore()
	store.index.CertIndex["../evil"] = certcloset.CertificateEntry{
		Domain: "../evil", ExpirationDate: exp,
	}
	store.retrieveMap["../evil"] = &certcloset.Certificate{
		Domain:      "../evil",
		Certificate: []byte("CERT"),
		PrivateKey:  []byte("KEY"),
	}

	a := &App{closet: store, config: Config{}}
	cfg := SyncConfig{}
	cfg.Traefik.LocalStore = localDir

	if err := a.syncCerts(cfg); err == nil {
		t.Fatal("syncCerts must fail when a certificate cannot be written")
	}

	local, err := certcloset.NewLocalCertCloset(certcloset.Config{}, localDir)
	if err != nil {
		t.Fatalf("NewLocalCertCloset: %v", err)
	}
	if _, ok := local.GetIndex().CertIndex["../evil"]; ok {
		t.Fatal("failed write must not advance local index")
	}
}

func TestSyncCertsRemovesLocalOnlyEntry(t *testing.T) {
	localDir := t.TempDir()
	exp := time.Now().AddDate(1, 0, 0)

	certDir := filepath.Join(localDir, "old.com")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, CERT_EXT), []byte("OLD-CERT"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, KEY_EXT), []byte("OLD-KEY"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	local, err := certcloset.NewLocalCertCloset(certcloset.Config{}, localDir)
	if err != nil {
		t.Fatalf("NewLocalCertCloset: %v", err)
	}
	local.GetIndex().Add(certcloset.CertificateEntry{Domain: "old.com", ExpirationDate: exp})
	if err := local.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	a := &App{closet: newMockStore(), config: Config{}}
	cfg := SyncConfig{}
	cfg.Traefik.LocalStore = localDir

	if err := a.syncCerts(cfg); err != nil {
		t.Fatalf("syncCerts: %v", err)
	}

	localAfter, err := certcloset.NewLocalCertCloset(certcloset.Config{}, localDir)
	if err != nil {
		t.Fatalf("NewLocalCertCloset after sync: %v", err)
	}
	if _, ok := localAfter.GetIndex().CertIndex["old.com"]; ok {
		t.Fatal("local-only index entry must be removed")
	}
	if _, err := os.Stat(certDir); !os.IsNotExist(err) {
		t.Fatalf("local-only certificate directory must be removed, stat err=%v", err)
	}
}

// Ensure mockStoreWithRetrieve satisfies certStore.
var _ certStore = (*mockStoreWithRetrieve)(nil)

// Verify StoreCertificate is still correctly delegated.
func (m *mockStoreWithRetrieve) StoreCertificate(cert certificate.Resource) error {
	return m.mockStore.StoreCertificate(cert)
}

func TestWriteHAProxyConfigDisabled(t *testing.T) {
	store := newMockStore()
	store.index.CertIndex["ha.com"] = certcloset.CertificateEntry{Domain: "ha.com"}
	a := &App{closet: store}
	cfg := SyncConfig{}
	// HAProxy.CertDir empty → no-op
	if err := a.writeHAProxyConfig(cfg); err != nil {
		t.Fatalf("writeHAProxyConfig: %v", err)
	}
}

func TestWriteHAProxyConfigBundlesOnly(t *testing.T) {
	dir := t.TempDir()
	localStore := t.TempDir()

	// Write separate cert+key files as syncCerts would.
	certDir := filepath.Join(localStore, "ha.com")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, CERT_EXT), []byte("CERT"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, KEY_EXT), []byte("KEY"), 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}

	store := newMockStore()
	store.index.CertIndex["ha.com"] = certcloset.CertificateEntry{Domain: "ha.com"}
	a := &App{closet: store}

	cfg := SyncConfig{}
	cfg.Traefik.LocalStore = localStore
	cfg.HAProxy.CertDir = dir

	if err := a.writeHAProxyConfig(cfg); err != nil {
		t.Fatalf("writeHAProxyConfig: %v", err)
	}

	bundle, err := os.ReadFile(filepath.Join(dir, "ha.com.pem"))
	if err != nil {
		t.Fatalf("bundle not written: %v", err)
	}
	if string(bundle) != "CERT\nKEY" {
		t.Errorf("bundle content mismatch: %q", bundle)
	}

	info, err := os.Stat(filepath.Join(dir, "ha.com.pem"))
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("bundle mode want 0600 got %o", info.Mode().Perm())
	}
}

func TestWriteHAProxyConfigCrtList(t *testing.T) {
	dir := t.TempDir()
	localStore := t.TempDir()
	crtListPath := filepath.Join(dir, "crt-list.txt")

	for _, domain := range []string{"a.com", "b.com"} {
		d := filepath.Join(localStore, domain)
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(d, CERT_EXT), []byte("CERT"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, KEY_EXT), []byte("KEY"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	store := newMockStore()
	store.index.CertIndex["a.com"] = certcloset.CertificateEntry{Domain: "a.com"}
	store.index.CertIndex["b.com"] = certcloset.CertificateEntry{Domain: "b.com"}
	a := &App{closet: store}

	cfg := SyncConfig{}
	cfg.Traefik.LocalStore = localStore
	cfg.HAProxy.CertDir = dir
	cfg.HAProxy.CrtListFile = crtListPath
	cfg.HAProxy.CertDirRef = "/etc/haproxy/certs"

	if err := a.writeHAProxyConfig(cfg); err != nil {
		t.Fatalf("writeHAProxyConfig: %v", err)
	}

	data, err := os.ReadFile(crtListPath)
	if err != nil {
		t.Fatalf("crt-list not written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "/etc/haproxy/certs/a.com.pem a.com") {
		t.Errorf("crt-list missing a.com entry:\n%s", content)
	}
	if !strings.Contains(content, "/etc/haproxy/certs/b.com.pem b.com") {
		t.Errorf("crt-list missing b.com entry:\n%s", content)
	}
}

func TestWriteHAProxyConfigSkipsUnsafeDomain(t *testing.T) {
	dir := t.TempDir()
	localStore := t.TempDir()

	d := filepath.Join(localStore, "ok.com")
	if err := os.MkdirAll(d, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(d, CERT_EXT), []byte("CERT"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, KEY_EXT), []byte("KEY"), 0644); err != nil {
		t.Fatal(err)
	}

	store := newMockStore()
	store.index.CertIndex["ok.com"] = certcloset.CertificateEntry{Domain: "ok.com"}
	store.index.CertIndex["../evil"] = certcloset.CertificateEntry{Domain: "../evil"}
	a := &App{closet: store}

	cfg := SyncConfig{}
	cfg.Traefik.LocalStore = localStore
	cfg.HAProxy.CertDir = dir

	if err := a.writeHAProxyConfig(cfg); err != nil {
		t.Fatalf("writeHAProxyConfig: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ok.com.pem")); err != nil {
		t.Fatalf("expected safe bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "evil.pem")); err == nil {
		t.Fatal("unsafe bundle path should not be written")
	}
}
