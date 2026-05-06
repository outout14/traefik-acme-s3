package certcloset

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/go-acme/lego/v4/certificate"
)

// mockS3 is an in-memory implementation of s3API for unit tests.
type mockS3 struct {
	mu         sync.Mutex
	objects    map[string][]byte
	headObjErr error // when set, HeadObject returns this error instead of 404/200
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
	m.objects[*params.Key] = data
	return &s3.PutObjectOutput{}, nil
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
