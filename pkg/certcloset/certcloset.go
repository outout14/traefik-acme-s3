package certcloset

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
	Password       string `env:"CLOSET_PASSWORD" required:"" help:"Password to encrypt the certificates ([priv/pub]keys)."`
	Bucket         string `env:"CLOSET_BUCKET" required:"" help:"S3 bucket to use to store the certificates."`
	PushPrivateKey bool   `env:"PUSH_PRIVATE_KEY" default:"false" help:"Push the private key to the closet."`
}

func (c *Config) Validate() error {
	return nil
}

type CertCloset struct {
	index  CertificateList
	config Config
	s3     *s3.Client
}

func (g *CertCloset) initS3() error {
	// Create a new S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("unable to load AWS SDK config: %w", err)
	}
	g.s3 = s3.NewFromConfig(cfg)

	_, err = g.s3.HeadBucket(context.TODO(), &s3.HeadBucketInput{
		Bucket: &g.config.Bucket,
	})
	if err != nil {
		return fmt.Errorf("unable to access S3 bucket: %w", err)
	}
	return nil
}

func NewCertCloset(config Config) (*CertCloset, error) {
	cg := CertCloset{
		config: config,
	}
	if err := cg.initS3(); err != nil {
		return nil, err
	}
	err := cg.RetrieveIndex()
	if err != nil {
		return nil, err
	}

	return &cg, nil
}

func (c *CertCloset) GetIndex() CertificateList {
	return c.index
}
