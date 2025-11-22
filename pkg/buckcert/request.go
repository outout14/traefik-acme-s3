package buckcert

import (
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/providers/http/s3"
)

func (b *Buckcert) RequestCert(domains []string) (*certificate.Resource, error) {
	// Create the S3 HTTP-01 provider
	provider, err := s3.NewHTTPProvider(b.config.ChallengeBucket)
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 HTTP-01 provider: %w", err)
	}

	// Apply provider to the ACME client
	if err := b.client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, fmt.Errorf("failed to set HTTP-01 provider: %w", err)
	}

	// Build ACME request
	req := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	// Request certificate from Let's Encrypt
	cert, err := b.client.Certificate.Obtain(req)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate for %v: %w", domains, err)
	}

	return cert, nil
}
