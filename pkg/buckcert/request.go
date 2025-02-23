package buckcert

import (
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/providers/http/s3"
)

func (c *Buckcert) RequestCert(domains []string) (*certificate.Resource, error) {
	provider, err := s3.NewHTTPProvider(c.config.ChallengeBucket)
	if err != nil {
		return nil, err
	}

	c.client.Challenge.SetHTTP01Provider(provider)

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  false,
	}

	certificates, err := c.client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	return certificates, nil
}
