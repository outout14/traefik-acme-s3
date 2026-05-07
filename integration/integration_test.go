//go:build integration

// Package integration contains end-to-end tests that require external services.
// Run with: go test -tags integration ./integration/...
package integration

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	gofakes3 "github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	pebbleCA "github.com/letsencrypt/pebble/v2/ca"
	pebbleDB "github.com/letsencrypt/pebble/v2/db"
	pebbleVA "github.com/letsencrypt/pebble/v2/va"
	pebbleWFE "github.com/letsencrypt/pebble/v2/wfe"

	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
)

// ---------- infrastructure helpers ----------

// startFakeS3 spins up an in-memory S3 server and returns a configured client.
// All listed buckets are created. Caller must call the returned cleanup func.
func startFakeS3(t *testing.T, buckets ...string) (*s3.Client, func()) {
	t.Helper()

	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())

	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test", "test", ""),
		),
	)
	if err != nil {
		ts.Close()
		t.Fatalf("aws config: %v", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ts.URL)
		o.UsePathStyle = true
	})

	for _, b := range buckets {
		if _, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
			Bucket: aws.String(b),
		}); err != nil {
			ts.Close()
			t.Fatalf("create bucket %q: %v", b, err)
		}
	}

	return client, ts.Close
}

// startPebble starts an in-process ACME server with challenge validation disabled.
// Returns a TLS test server (caller must defer ts.Close()) and its directory URL.
func startPebble(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	// Disable actual HTTP/TLS challenge verification so tests do not need a real HTTP server.
	t.Setenv("PEBBLE_VA_ALWAYS_VALID", "1")
	// Disable the random VA sleep for faster tests.
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")

	logger := log.New(io.Discard, "", 0)

	memDB := pebbleDB.NewMemoryStore()
	profiles := map[string]pebbleCA.Profile{
		"default": {Description: "default profile", ValidityPeriod: 0},
	}
	caImpl := pebbleCA.New(logger, memDB, "", "ecdsa", 0, 1, profiles)
	vaImpl := pebbleVA.New(logger, 80, 443, false, "", memDB)
	// retryAfterAuthz and retryAfterOrder must be > 0 (Intn panics on 0).
	wfe := pebbleWFE.New(logger, memDB, vaImpl, caImpl, nil, false, false, 1, 1)

	ts := httptest.NewTLSServer(wfe.Handler())
	return ts, ts.URL + "/dir"
}

// nopProvider satisfies challenge.Provider without doing anything.
// Safe when the ACME server has PEBBLE_VA_ALWAYS_VALID=1.
type nopProvider struct{}

func (n *nopProvider) Present(_, _, _ string) error { return nil }
func (n *nopProvider) CleanUp(_, _, _ string) error { return nil }

var _ challenge.Provider = (*nopProvider)(nil)

// ---------- tests ----------

// TestACMEObtainAndStoreCert exercises the full cert lifecycle:
// pebble ACME server → lego client → CertCloset (gofakes3).
func TestACMEObtainAndStoreCert(t *testing.T) {
	s3Client, closeS3 := startFakeS3(t, "certs")
	defer closeS3()

	pebbleTS, dirURL := startPebble(t)
	defer pebbleTS.Close()

	userKeyFile := filepath.Join(t.TempDir(), "le_user.json")

	bc, err := buckcert.NewBuckcert(buckcert.Config{
		Email:           "test@example.com",
		CaURL:           dirURL,
		KeyType:         "P256",
		ChallengeBucket: "certs", // not actually used — nopProvider bypasses S3
		UserKeyPath:     userKeyFile,
		HTTPClient:      pebbleTS.Client(), // trust pebble's self-signed cert
	})
	if err != nil {
		t.Fatalf("NewBuckcert: %v", err)
	}

	cert, err := bc.RequestCertWithProvider([]string{"test.example.com"}, &nopProvider{})
	if err != nil {
		t.Fatalf("RequestCertWithProvider: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("obtained certificate is empty")
	}

	closet, err := certcloset.NewCertClosetWithS3Client(certcloset.Config{
		Password:       "integration-password",
		Bucket:         "certs",
		PushPrivateKey: true,
	}, s3Client)
	if err != nil {
		t.Fatalf("NewCertClosetWithS3Client: %v", err)
	}

	if err := closet.StoreCertificate(*cert); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}

	got, err := closet.RetrieveCertificate("test.example.com")
	if err != nil {
		t.Fatalf("RetrieveCertificate: %v", err)
	}

	if got.Domain != "test.example.com" {
		t.Errorf("domain want %q got %q", "test.example.com", got.Domain)
	}
	if !bytes.Equal(got.Certificate, cert.Certificate) {
		t.Error("certificate bytes differ after round-trip")
	}
	if !bytes.Equal(got.PrivateKey, cert.PrivateKey) {
		t.Error("private key mismatch after AES encrypt/decrypt round-trip")
	}

	// Index must be updated
	entry, ok := closet.GetIndex().CertIndex["test.example.com"]
	if !ok {
		t.Fatal("cert not reflected in index after StoreCertificate")
	}
	if !entry.ExpirationDate.After(time.Now()) {
		t.Errorf("index expiry must be in the future, got %v", entry.ExpirationDate)
	}
}

// TestIndexPersistenceViaS3 verifies SaveIndex → reload round-trip through gofakes3.
func TestIndexPersistenceViaS3(t *testing.T) {
	s3Client, closeS3 := startFakeS3(t, "idx-bucket")
	defer closeS3()

	cfg := certcloset.Config{Password: "pw", Bucket: "idx-bucket"}
	exp := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)

	c1, err := certcloset.NewCertClosetWithS3Client(cfg, s3Client)
	if err != nil {
		t.Fatalf("open c1: %v", err)
	}
	c1.AddToIndex(certcloset.CertificateEntry{Domain: "persist.com", ExpirationDate: exp})
	if err := c1.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	c2, err := certcloset.NewCertClosetWithS3Client(cfg, s3Client)
	if err != nil {
		t.Fatalf("open c2: %v", err)
	}
	entry, ok := c2.GetIndex().CertIndex["persist.com"]
	if !ok {
		t.Fatal("index entry lost after reload")
	}
	if !entry.ExpirationDate.Equal(exp) {
		t.Errorf("expiry want %v got %v", exp, entry.ExpirationDate)
	}
}

// TestSyncLocalClosetWithS3Backend verifies that a local closet correctly diffs against
// an S3-backed closet and that cert files land on disk.
func TestSyncLocalClosetWithS3Backend(t *testing.T) {
	const domain = "sync.example.com"

	s3Client, closeS3 := startFakeS3(t, "sync-certs")
	defer closeS3()

	closetCfg := certcloset.Config{
		Password:       "sync-pw",
		Bucket:         "sync-certs",
		PushPrivateKey: true,
	}

	remote, err := certcloset.NewCertClosetWithS3Client(closetCfg, s3Client)
	if err != nil {
		t.Fatalf("remote closet: %v", err)
	}

	// Store a fake cert in S3
	fakeCert := []byte("FAKE-CERT-PEM")
	fakeKey := []byte("FAKE-KEY-PEM")
	res := certificate.Resource{
		Domain:      domain,
		Certificate: fakeCert,
		PrivateKey:  fakeKey,
	}
	if err := remote.StoreCertificate(res); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}
	if err := remote.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	// Local starts empty — diff should include domain
	localDir := t.TempDir()
	local, err := certcloset.NewLocalCertCloset(closetCfg, localDir)
	if err != nil {
		t.Fatalf("local closet: %v", err)
	}

	diff := remote.GetIndex().GetDiff(local.GetIndex())
	if len(diff) != 1 || diff[0].Domain != domain {
		t.Fatalf("expected diff [%s] got %v", domain, diff)
	}

	// Retrieve from S3 and write to disk (what app.syncCerts does)
	retrieved, err := remote.RetrieveCertificate(domain)
	if err != nil {
		t.Fatalf("RetrieveCertificate: %v", err)
	}
	if !bytes.Equal(retrieved.PrivateKey, fakeKey) {
		t.Error("private key mismatch after AES round-trip")
	}
	if !bytes.Equal(retrieved.Certificate, fakeCert) {
		t.Error("certificate bytes mismatch")
	}

	certDir := filepath.Join(localDir, domain)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), retrieved.Certificate, 0644); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), retrieved.PrivateKey, 0644); err != nil {
		t.Fatalf("write key.pem: %v", err)
	}

	// Integrity should now pass for local closet
	local.GetIndex().Add(certcloset.CertificateEntry{
		Domain:         domain,
		ExpirationDate: time.Now().AddDate(0, 0, 89),
	})
	failed := local.CheckIntegrity()
	if len(failed) != 0 {
		t.Errorf("integrity check failed for %v — cert files should exist on disk", failed)
	}
}
