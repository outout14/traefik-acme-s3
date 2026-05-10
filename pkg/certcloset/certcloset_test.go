package certcloset

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/go-acme/lego/v4/certificate"
)

// selfSignedCertPEM returns a minimal self-signed PEM cert with the given NotAfter.
func selfSignedCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// mockS3 is an in-memory implementation of s3API for unit tests.
type mockS3 struct {
	mu               sync.Mutex
	objects          map[string][]byte
	headObjErr       error // when set, HeadObject returns this error instead of 404/200
	putCalls         int
	noConditionalPut bool // simulate backends that reject IfNoneMatch (e.g. OVHcloud, Ceph)
}

func newMockS3() *mockS3 { return &mockS3{objects: make(map[string][]byte)} }

func notFoundErr() error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{
				Response: &http.Response{StatusCode: http.StatusNotFound},
			},
		},
	}
}

func preconditionErr() error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{
				Response: &http.Response{StatusCode: http.StatusPreconditionFailed},
			},
		},
	}
}

func notImplementedErr() error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{
				Response: &http.Response{StatusCode: http.StatusNotImplemented},
			},
		},
	}
}

func (m *mockS3) HeadBucket(_ context.Context, _ *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

func (m *mockS3) GetObject(_ context.Context, params *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[*params.Key]
	if !ok {
		return nil, notFoundErr()
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func (m *mockS3) PutObject(_ context.Context, params *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	if params.IfNoneMatch != nil && *params.IfNoneMatch == "*" {
		if m.noConditionalPut {
			return nil, notImplementedErr()
		}
		if _, exists := m.objects[*params.Key]; exists {
			return nil, preconditionErr()
		}
	}
	m.objects[*params.Key] = data
	m.putCalls++
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3) DeleteObject(_ context.Context, params *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, *params.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (m *mockS3) HeadObject(_ context.Context, params *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.headObjErr != nil {
		return nil, m.headObjErr
	}
	if _, ok := m.objects[*params.Key]; !ok {
		return nil, notFoundErr()
	}
	return &s3.HeadObjectOutput{}, nil
}

func newTestCloset(t *testing.T, pushKey bool) *CertCloset {
	t.Helper()
	c := &CertCloset{
		config: Config{
			Password:       "test-password-any-length-is-fine",
			Bucket:         "test-bucket",
			PushPrivateKey: pushKey,
		},
		s3: newMockS3(),
	}
	// retrieveIndex on empty mock → creates empty index (404 → new index)
	if err := c.retrieveIndex(); err != nil {
		t.Fatalf("retrieveIndex: %v", err)
	}
	return c
}

func TestRetrieveIndexEmptyBucket(t *testing.T) {
	c := newTestCloset(t, false)
	if c.index.CertIndex == nil {
		t.Fatal("empty index must be initialized, not nil")
	}
	if len(c.index.CertIndex) != 0 {
		t.Fatalf("want 0 entries got %d", len(c.index.CertIndex))
	}
}

func TestSaveAndReloadIndex(t *testing.T) {
	c := newTestCloset(t, false)
	exp := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	c.index.CertIndex["reload.com"] = CertificateEntry{Domain: "reload.com", ExpirationDate: exp}
	c.dirty = true

	if err := c.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	// Reload index from the same mock S3
	c2 := &CertCloset{config: c.config, s3: c.s3}
	if err := c2.retrieveIndex(); err != nil {
		t.Fatalf("retrieveIndex after save: %v", err)
	}
	entry, ok := c2.index.CertIndex["reload.com"]
	if !ok {
		t.Fatal("entry not found after reload")
	}
	if !entry.ExpirationDate.Equal(exp) {
		t.Errorf("expiry want %v got %v", exp, entry.ExpirationDate)
	}
}

func TestStoreCertificateNoPushKey(t *testing.T) {
	c := newTestCloset(t, false)
	res := certificate.Resource{
		Domain:      "nopush.com",
		Certificate: []byte("CERT-BYTES"),
		PrivateKey:  []byte("KEY-BYTES"),
	}
	if err := c.StoreCertificate(res); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}
	if _, ok := c.index.CertIndex["nopush.com"]; !ok {
		t.Fatal("index not updated after store")
	}
}

func TestStoreCertificateWithPushKey(t *testing.T) {
	c := newTestCloset(t, true)
	res := certificate.Resource{
		Domain:      "push.com",
		Certificate: []byte("CERT-BYTES"),
		PrivateKey:  []byte("PRIVATE-KEY-DATA"),
	}
	if err := c.StoreCertificate(res); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}
}

func TestStoreCertificateSetsIndexExpiry89Days(t *testing.T) {
	c := newTestCloset(t, false)
	before := time.Now()
	res := certificate.Resource{
		Domain:      "expiry.com",
		Certificate: []byte("CERT"),
	}
	if err := c.StoreCertificate(res); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}
	after := time.Now()

	entry, ok := c.index.CertIndex["expiry.com"]
	if !ok {
		t.Fatal("expiry.com not in index")
	}

	wantMin := before.AddDate(0, 0, 89)
	wantMax := after.AddDate(0, 0, 89)

	if entry.ExpirationDate.Before(wantMin) || entry.ExpirationDate.After(wantMax) {
		t.Errorf("expiry %v not in expected range [%v, %v]", entry.ExpirationDate, wantMin, wantMax)
	}
}

func TestStoreCertificateSetsIndexExpiryFromPEM(t *testing.T) {
	c := newTestCloset(t, false)
	wantExpiry := time.Date(2028, 6, 15, 0, 0, 0, 0, time.UTC)
	certPEM := selfSignedCertPEM(t, wantExpiry)

	res := certificate.Resource{
		Domain:      "pem-expiry.com",
		Certificate: certPEM,
	}
	if err := c.StoreCertificate(res); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}

	entry, ok := c.index.CertIndex["pem-expiry.com"]
	if !ok {
		t.Fatal("pem-expiry.com not in index")
	}
	if !entry.ExpirationDate.Equal(wantExpiry) {
		t.Errorf("expiry want %v got %v", wantExpiry, entry.ExpirationDate)
	}
}

func TestRetrieveCertificateRoundTrip(t *testing.T) {
	c := newTestCloset(t, false)
	original := certificate.Resource{
		Domain:      "roundtrip.com",
		Certificate: []byte("CERT-PEM-DATA"),
		PrivateKey:  nil, // not stored when PushPrivateKey=false
	}
	if err := c.StoreCertificate(original); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}

	got, err := c.RetrieveCertificate("roundtrip.com")
	if err != nil {
		t.Fatalf("RetrieveCertificate: %v", err)
	}
	if got.Domain != "roundtrip.com" {
		t.Errorf("domain want %q got %q", "roundtrip.com", got.Domain)
	}
	if !bytes.Equal(got.Certificate, original.Certificate) {
		t.Errorf("cert bytes mismatch")
	}
}

func TestRetrieveCertificateEncryptDecryptKey(t *testing.T) {
	c := newTestCloset(t, true)
	plainKey := []byte("-----BEGIN EC PRIVATE KEY-----\nfakepemdata\n-----END EC PRIVATE KEY-----")
	res := certificate.Resource{
		Domain:      "encrypted.com",
		Certificate: []byte("CERT-PEM"),
		PrivateKey:  plainKey,
	}
	if err := c.StoreCertificate(res); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}

	got, err := c.RetrieveCertificate("encrypted.com")
	if err != nil {
		t.Fatalf("RetrieveCertificate: %v", err)
	}
	if !bytes.Equal(got.PrivateKey, plainKey) {
		t.Errorf("private key mismatch after encrypt/decrypt round-trip")
	}
}

func TestRetrieveCertificateNotFound(t *testing.T) {
	c := newTestCloset(t, false)
	_, err := c.RetrieveCertificate("ghost.com")
	if err == nil {
		t.Fatal("expected error for missing certificate")
	}
}

func TestCertificateExistsTrue(t *testing.T) {
	c := newTestCloset(t, false)
	res := certificate.Resource{
		Domain:      "exists.com",
		Certificate: []byte("CERT"),
	}
	if err := c.StoreCertificate(res); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}

	ok, err := c.CertificateExists("exists.com")
	if err != nil {
		t.Fatalf("CertificateExists: %v", err)
	}
	if !ok {
		t.Fatal("want exists=true")
	}
}

func TestCertificateExistsFalse(t *testing.T) {
	c := newTestCloset(t, false)
	ok, err := c.CertificateExists("ghost.com")
	if err != nil {
		t.Fatalf("CertificateExists: %v", err)
	}
	if ok {
		t.Fatal("want exists=false for missing cert")
	}
}

func TestGetIndex(t *testing.T) {
	c := newTestCloset(t, false)
	idx := c.GetIndex()
	if idx == nil {
		t.Fatal("GetIndex returned nil")
	}
}

func TestIsErrNotFound(t *testing.T) {
	if !IsErrNotFound(notFoundErr()) {
		t.Fatal("notFoundErr() must satisfy IsErrNotFound")
	}
	if IsErrNotFound(nil) {
		t.Fatal("nil must not satisfy IsErrNotFound")
	}
}

func TestIsErrNotFoundNon404(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusInternalServerError, http.StatusBadRequest} {
		err := &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{
					Response: &http.Response{StatusCode: code},
				},
			},
		}
		if IsErrNotFound(err) {
			t.Errorf("HTTP %d must not satisfy IsErrNotFound", code)
		}
	}
}

func TestConfigValidateEmptyPassword(t *testing.T) {
	cfg := Config{Password: "", Bucket: "b"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty password must fail validation")
	}
}

func TestConfigValidateNonEmpty(t *testing.T) {
	cfg := Config{Password: "secret", Bucket: "b"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("non-empty password must pass: %v", err)
	}
}

func TestSaveIndexNoOpWhenClean(t *testing.T) {
	c := newTestCloset(t, false)
	mock := c.s3.(*mockS3)
	initialPuts := mock.putCalls
	if err := c.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	if mock.putCalls != initialPuts {
		t.Fatal("SaveIndex must be no-op when index is clean")
	}
}

func TestSaveIndexDirtyAfterStore(t *testing.T) {
	c := newTestCloset(t, false)
	mock := c.s3.(*mockS3)
	if err := c.StoreCertificate(certificate.Resource{Domain: "dirty.com", Certificate: []byte("CERT")}); err != nil {
		t.Fatal(err)
	}
	putsBefore := mock.putCalls
	if err := c.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	if mock.putCalls == putsBefore {
		t.Fatal("SaveIndex must write when index is dirty")
	}
	if c.dirty {
		t.Fatal("dirty flag must be cleared after successful save")
	}
}

func TestAcquireReleaseLock(t *testing.T) {
	c := newTestCloset(t, false)
	if err := c.AcquireLock(); err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	c.ReleaseLock()
	// After release, acquiring again must succeed.
	if err := c.AcquireLock(); err != nil {
		t.Fatalf("AcquireLock after release: %v", err)
	}
	c.ReleaseLock()
}

func TestAcquireLockRejectsActiveLock(t *testing.T) {
	c := newTestCloset(t, false)
	if err := c.AcquireLock(); err != nil {
		t.Fatalf("first AcquireLock: %v", err)
	}
	// Second acquire should fail — lock is fresh.
	if err := c.AcquireLock(); err == nil {
		t.Fatal("second AcquireLock must fail while lock is held")
	}
	c.ReleaseLock()
}

func TestAcquireLockRejectsActiveLockFromAnotherInstance(t *testing.T) {
	c1 := newTestCloset(t, false)
	if err := c1.AcquireLock(); err != nil {
		t.Fatalf("first AcquireLock: %v", err)
	}
	defer c1.ReleaseLock()

	c2 := &CertCloset{config: c1.config, s3: c1.s3}
	if err := c2.retrieveIndex(); err != nil {
		t.Fatalf("retrieveIndex: %v", err)
	}
	if err := c2.AcquireLock(); err == nil {
		t.Fatal("second instance must not acquire an active lock")
	}
}

func TestRefreshLockExtendsExpiry(t *testing.T) {
	c := newTestCloset(t, false)
	if err := c.AcquireLock(); err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	mock := c.s3.(*mockS3)

	mock.mu.Lock()
	var rec lockRecord
	if err := json.Unmarshal(mock.objects[lockKey], &rec); err != nil {
		mock.mu.Unlock()
		t.Fatalf("unmarshal lock: %v", err)
	}
	rec.ExpiresAt = time.Now().Add(time.Minute)
	data, _ := json.Marshal(&rec)
	mock.objects[lockKey] = data
	mock.mu.Unlock()

	if err := c.RefreshLock(); err != nil {
		t.Fatalf("RefreshLock: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if err := json.Unmarshal(mock.objects[lockKey], &rec); err != nil {
		t.Fatalf("unmarshal refreshed lock: %v", err)
	}
	if time.Until(rec.ExpiresAt) < 4*time.Minute {
		t.Fatalf("RefreshLock did not extend expiry enough: %v", rec.ExpiresAt)
	}
}

func TestReleaseLockDoesNotDeleteForeignLock(t *testing.T) {
	c := newTestCloset(t, false)
	if err := c.AcquireLock(); err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	mock := c.s3.(*mockS3)

	foreign, _ := json.Marshal(&lockRecord{
		Hostname:   "other",
		OwnerID:    "foreign-token",
		AcquiredAt: time.Now(),
		ExpiresAt:  time.Now().Add(lockTTL),
	})
	mock.mu.Lock()
	mock.objects[lockKey] = foreign
	mock.mu.Unlock()

	c.ReleaseLock()

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if _, ok := mock.objects[lockKey]; !ok {
		t.Fatal("ReleaseLock must not delete a lock owned by another instance")
	}
}

func TestCertificateExistsS3Error(t *testing.T) {
	c := newTestCloset(t, false)
	mock := c.s3.(*mockS3)
	mock.headObjErr = &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{
				Response: &http.Response{StatusCode: http.StatusForbidden},
			},
		},
	}

	ok, err := c.CertificateExists("any.com")
	if err == nil {
		t.Fatal("expected error for non-404 S3 error")
	}
	if ok {
		t.Fatal("exists must be false when S3 returns an error")
	}
}

func TestACMEUserEncryptedS3RoundTrip(t *testing.T) {
	c := newTestCloset(t, false)
	mock := c.s3.(*mockS3)
	plain := []byte(`{"email":"admin@example.com","key":"secret-key"}`)

	stored, err := c.StoreACMEUserIfNotExists(plain)
	if err != nil {
		t.Fatalf("StoreACMEUserIfNotExists: %v", err)
	}
	if !stored {
		t.Fatal("first StoreACMEUserIfNotExists must store")
	}

	mock.mu.Lock()
	encrypted := append([]byte(nil), mock.objects[acmeUserKey]...)
	mock.mu.Unlock()
	if bytes.Contains(encrypted, []byte("secret-key")) {
		t.Fatal("ACME user must be encrypted in S3")
	}

	got, exists, err := c.LoadACMEUser()
	if err != nil {
		t.Fatalf("LoadACMEUser: %v", err)
	}
	if !exists {
		t.Fatal("ACME user must exist")
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("ACME user mismatch: %q", got)
	}

	stored, err = c.StoreACMEUserIfNotExists([]byte(`{"different":true}`))
	if err != nil {
		t.Fatalf("second StoreACMEUserIfNotExists: %v", err)
	}
	if stored {
		t.Fatal("second StoreACMEUserIfNotExists must not overwrite")
	}
}

// TestACMEUserIfNotExistsFallback covers backends (OVHcloud, Ceph) that return
// 501 for conditional PUTs. The fallback uses HeadObject+PutObject.
func TestACMEUserIfNotExistsFallback(t *testing.T) {
	c := newTestCloset(t, false)
	mock := c.s3.(*mockS3)
	mock.noConditionalPut = true
	plain := []byte(`{"email":"admin@example.com","key":"secret-key"}`)

	stored, err := c.StoreACMEUserIfNotExists(plain)
	if err != nil {
		t.Fatalf("StoreACMEUserIfNotExists (fallback): %v", err)
	}
	if !stored {
		t.Fatal("first call must store via fallback")
	}

	got, exists, err := c.LoadACMEUser()
	if err != nil {
		t.Fatalf("LoadACMEUser after fallback store: %v", err)
	}
	if !exists {
		t.Fatal("ACME user must exist after fallback store")
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("ACME user mismatch: %q", got)
	}

	stored, err = c.StoreACMEUserIfNotExists([]byte(`{"different":true}`))
	if err != nil {
		t.Fatalf("second StoreACMEUserIfNotExists (fallback): %v", err)
	}
	if stored {
		t.Fatal("second fallback call must not overwrite existing user")
	}
}
