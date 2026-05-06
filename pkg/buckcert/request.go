package buckcert

import (
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	legoS3 "github.com/go-acme/lego/v4/providers/http/s3"
)

// RequestCert obtains a certificate for the given domains using the configured S3 HTTP-01 provider.
func (b *Buckcert) RequestCert(domains []string) (*certificate.Resource, error) {
	provider, err := legoS3.NewHTTPProvider(b.config.ChallengeBucket)
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 HTTP-01 provider: %w", err)
	}
	return b.requestCertWithProvider(domains, provider)
}

// RequestCertWithProvider obtains a certificate using the given HTTP-01 challenge provider.
// Use in integration tests to bypass the S3 challenge provider.
func (b *Buckcert) RequestCertWithProvider(domains []string, provider challenge.Provider) (*certificate.Resource, error) {
	return b.requestCertWithProvider(domains, provider)
}

func (b *Buckcert) requestCertWithProvider(domains []string, provider challenge.Provider) (*certificate.Resource, error) {
	if err := b.client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, fmt.Errorf("failed to set HTTP-01 provider: %w", err)
	}

	req := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	cert, err := b.client.Certificate.Obtain(req)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate for %v: %w", domains, err)
	}

	return cert, nil
}
