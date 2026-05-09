package certcloset

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
	Password       string `env:"CLOSET_PASSWORD" required:"" help:"Password used to encrypt stored certificates."`
	Bucket         string `env:"CLOSET_BUCKET" required:"" help:"S3 bucket used for storing certificates and metadata."`
	PushPrivateKey bool   `env:"CLOSET_PUSH_PRIVATE_KEY" default:"true" help:"Whether the private key should also be stored."`
}

func (c *Config) Validate() error {
	if c.Password == "" {
		return fmt.Errorf("CLOSET_PASSWORD must not be empty")
	}
	return nil
}

// s3API is the subset of s3.Client methods used by CertCloset.
type s3API interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

type CertCloset struct {
	mu        sync.Mutex
	index     CertificateList
	config    Config
	s3        s3API
	dirty     bool
	lockToken string
}

// initS3 initializes the AWS S3 client and validates bucket access.
func (c *CertCloset) initS3() error {
	ctx := context.TODO()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	c.s3 = s3.NewFromConfig(cfg)

	_, err = c.s3.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: &c.config.Bucket,
	})
	if err != nil {
		return fmt.Errorf("unable to access S3 bucket %q: %w", c.config.Bucket, err)
	}

	return nil
}

func NewCertCloset(cfg Config) (*CertCloset, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	c := &CertCloset{config: cfg}

	if err := c.initS3(); err != nil {
		return nil, err
	}

	if err := c.retrieveIndex(); err != nil {
		return nil, fmt.Errorf("failed to load certificate index: %w", err)
	}

	return c, nil
}

// NewCertClosetWithS3Client creates a CertCloset using a pre-configured S3 client.
// Use in integration tests to supply a fake or local S3 backend.
func NewCertClosetWithS3Client(cfg Config, client *s3.Client) (*CertCloset, error) {
	c := &CertCloset{config: cfg, s3: client}
	if err := c.retrieveIndex(); err != nil {
		return nil, fmt.Errorf("failed to load certificate index: %w", err)
	}
	return c, nil
}

// GetIndex returns the internal index. The returned pointer is not safe to write
// concurrently with StoreCertificate or RemoveFromIndex.
func (c *CertCloset) GetIndex() *CertificateList {
	return &c.index
}

// s3PutWithRetry uploads data to S3 with up to 3 attempts and exponential backoff (2s/4s/8s).
func (c *CertCloset) s3PutWithRetry(key string, data []byte) error {
	backoff := 2 * time.Second
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}
		_, lastErr = c.s3.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: &c.config.Bucket,
			Key:    &key,
			Body:   bytes.NewReader(data),
		})
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

// SaveIndex persists the index to S3 with up to 3 attempts and exponential backoff.
// No-op when index is unchanged.
func (c *CertCloset) SaveIndex() error {
	c.mu.Lock()
	dirty := c.dirty
	c.mu.Unlock()
	if !dirty {
		return nil
	}

	data, err := json.Marshal(c.index)
	if err != nil {
		return fmt.Errorf("failed to marshal index JSON: %w", err)
	}

	if err := c.s3PutWithRetry(CerticateIndexFile, data); err != nil {
		return fmt.Errorf("failed to upload index after 3 attempts: %w", err)
	}

	c.mu.Lock()
	c.dirty = false
	c.mu.Unlock()
	return nil
}

// AddToIndex adds an entry to the in-memory index and marks it dirty.
func (c *CertCloset) AddToIndex(entry CertificateEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.index.Add(entry)
	c.dirty = true
}

// RemoveFromIndex removes a domain from the in-memory index and marks it dirty.
func (c *CertCloset) RemoveFromIndex(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.index.Remove(domain)
	c.dirty = true
}
