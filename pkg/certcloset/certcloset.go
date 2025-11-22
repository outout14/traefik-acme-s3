package certcloset

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
	Password       string `env:"CLOSET_PASSWORD" required:"" help:"Password used to encrypt stored certificates."`
	Bucket         string `env:"CLOSET_BUCKET" required:"" help:"S3 bucket used for storing certificates and metadata."`
	PushPrivateKey bool   `env:"PUSH_PRIVATE_KEY" default:"true" help:"Whether the private key should also be stored."`
}

func (c *Config) Validate() error {
	// Add validation rules if needed, currently always valid
	return nil
}

type CertCloset struct {
	index  CertificateList
	config Config
	s3     *s3.Client
}

// initS3 initializes the AWS S3 client and validates bucket access.
func (c *CertCloset) initS3() error {
	ctx := context.TODO()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	c.s3 = s3.NewFromConfig(cfg)

	// Validate bucket existence + permission
	_, err = c.s3.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: &c.config.Bucket,
	})
	if err != nil {
		return fmt.Errorf("unable to access S3 bucket %q: %w", c.config.Bucket, err)
	}

	return nil
}

func NewCertCloset(cfg Config) (*CertCloset, error) {
	c := &CertCloset{
		config: cfg,
	}

	if err := c.initS3(); err != nil {
		return nil, err
	}

	if err := c.retrieveIndex(); err != nil {
		return nil, fmt.Errorf("failed to load certificate index: %w", err)
	}

	return c, nil
}

// GetIndex returns the internal index safely.
// Returning a pointer avoids accidental copies and keeps behavior consistent.
func (c *CertCloset) GetIndex() *CertificateList {
	return &c.index
}

// SaveIndex persists the index to S3 (certificate metadata JSON).
func (c *CertCloset) SaveIndex() error {
	data, err := json.Marshal(c.index)
	if err != nil {
		return fmt.Errorf("failed to marshal index JSON: %w", err)
	}

	_, err = c.s3.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &CerticateIndexFile, // keep original constant if defined elsewhere
		Body:   bytes.NewReader(data),
	})

	if err != nil {
		return fmt.Errorf("failed to upload index to S3: %w", err)
	}

	return nil
}
