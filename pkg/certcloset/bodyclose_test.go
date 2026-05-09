package certcloset

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type trackingReadCloser struct {
	*bytes.Reader
	closed *bool
}

func (t *trackingReadCloser) Close() error {
	*t.closed = true
	return nil
}

type trackingS3 struct {
	objects map[string][]byte
	closed  map[string]*bool
}

func newTrackingS3() *trackingS3 {
	return &trackingS3{
		objects: make(map[string][]byte),
		closed:  make(map[string]*bool),
	}
}

func (m *trackingS3) GetObject(_ context.Context, params *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := *params.Key
	data, ok := m.objects[key]
	if !ok {
		return nil, notFoundErr()
	}
	c := false
	m.closed[key] = &c
	return &s3.GetObjectOutput{
		Body: &trackingReadCloser{
			Reader: bytes.NewReader(data),
			closed: &c,
		},
	}, nil
}

func (m *trackingS3) PutObject(_ context.Context, params *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	data, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	m.objects[*params.Key] = data
	return &s3.PutObjectOutput{}, nil
}

func (m *trackingS3) DeleteObject(_ context.Context, params *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	delete(m.objects, *params.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (m *trackingS3) HeadBucket(_ context.Context, _ *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

func (m *trackingS3) HeadObject(_ context.Context, params *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if _, ok := m.objects[*params.Key]; !ok {
		return nil, notFoundErr()
	}
	return &s3.HeadObjectOutput{}, nil
}

func TestRetrieveIndexClosesBody(t *testing.T) {
	s3m := newTrackingS3()
	s3m.objects[CerticateIndexFile] = []byte(`{"cert_index":{}}`)
	c := &CertCloset{config: Config{Bucket: "b"}, s3: s3m}

	if err := c.retrieveIndex(); err != nil {
		t.Fatalf("retrieveIndex: %v", err)
	}
	if s3m.closed[CerticateIndexFile] == nil || !*s3m.closed[CerticateIndexFile] {
		t.Fatal("retrieveIndex must close response body")
	}
}

func TestRetrieveCertificateClosesBody(t *testing.T) {
	s3m := newTrackingS3()
	payload, _ := json.Marshal(&Certificate{Certificate: []byte("CERT"), PrivateKey: []byte("KEY")})
	s3m.objects["example.com"] = payload
	c := &CertCloset{config: Config{Bucket: "b", PushPrivateKey: false}, s3: s3m}

	if _, err := c.RetrieveCertificate("example.com"); err != nil {
		t.Fatalf("RetrieveCertificate: %v", err)
	}
	if s3m.closed["example.com"] == nil || !*s3m.closed["example.com"] {
		t.Fatal("RetrieveCertificate must close response body")
	}
}

func TestLoadFailureStateClosesBody(t *testing.T) {
	s3m := newTrackingS3()
	s3m.objects[failureStateKey] = []byte(`{"last_failure":{"a.com":"2026-01-02T03:04:05Z"}}`)
	c := &CertCloset{config: Config{Bucket: "b"}, s3: s3m}

	if _, err := c.LoadFailureState(); err != nil {
		t.Fatalf("LoadFailureState: %v", err)
	}
	if s3m.closed[failureStateKey] == nil || !*s3m.closed[failureStateKey] {
		t.Fatal("LoadFailureState must close response body")
	}
}

func TestLoadACMEUserClosesBody(t *testing.T) {
	s3m := newTrackingS3()
	c := &CertCloset{config: Config{Bucket: "b", Password: "secret"}, s3: s3m}
	encrypted, err := encryptAES(c.deriveKey(), []byte(`{"email":"a@example.com","key":"k"}`))
	if err != nil {
		t.Fatalf("encryptAES: %v", err)
	}
	s3m.objects[acmeUserKey] = encrypted

	if _, _, err := c.LoadACMEUser(); err != nil {
		t.Fatalf("LoadACMEUser: %v", err)
	}
	if s3m.closed[acmeUserKey] == nil || !*s3m.closed[acmeUserKey] {
		t.Fatal("LoadACMEUser must close response body")
	}
}

func TestLoadRolloverStateClosesBody(t *testing.T) {
	s3m := newTrackingS3()
	key := rolloverPrefix + "a.com.json"
	s3m.objects[key] = []byte(`{"phase":"pre-publishing","old_tlsa_hex":"","new_tlsa_hex":"abc","phase_started_at":"2026-01-02T03:04:05Z","tlsa_ttl_seconds":60,"sync_lag_seconds":30}`)
	c := &CertCloset{config: Config{Bucket: "b"}, s3: s3m}

	if _, exists, err := c.LoadRolloverState("a.com"); err != nil || !exists {
		t.Fatalf("LoadRolloverState: exists=%v err=%v", exists, err)
	}
	if s3m.closed[key] == nil || !*s3m.closed[key] {
		t.Fatal("LoadRolloverState must close response body")
	}
}

func TestLoadPendingKeyClosesBody(t *testing.T) {
	s3m := newTrackingS3()
	c := &CertCloset{config: Config{Bucket: "b", Password: "secret"}, s3: s3m}
	encrypted, err := encryptAES(c.deriveKey(), []byte("pending-key"))
	if err != nil {
		t.Fatalf("encryptAES: %v", err)
	}
	key := pendingKeyPrefix + "a.com"
	s3m.objects[key] = encrypted

	if _, err := c.LoadPendingKey("a.com"); err != nil {
		t.Fatalf("LoadPendingKey: %v", err)
	}
	if s3m.closed[key] == nil || !*s3m.closed[key] {
		t.Fatal("LoadPendingKey must close response body")
	}
}

func TestAcquireLockClosesBody(t *testing.T) {
	s3m := newTrackingS3()
	rec, _ := json.Marshal(lockRecord{Hostname: "other", AcquiredAt: time.Now().Add(-10 * time.Minute)})
	s3m.objects[lockKey] = rec
	c := &CertCloset{config: Config{Bucket: "b"}, s3: s3m}

	if err := c.AcquireLock(); err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if s3m.closed[lockKey] == nil || !*s3m.closed[lockKey] {
		t.Fatal("AcquireLock must close response body")
	}
}
