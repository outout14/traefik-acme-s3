package certcloset

import (
	"github.com/go-acme/lego/v4/certificate"
)

// This struct is used for serializing the certificate to JSON to store in the S3 bucket
type Certificate struct {
	Certificate []byte `json:"cert"`
	PrivateKey  []byte `json:"privkey"`
	Domain      string `json:"-"`
}

func serializeCert(cert certificate.Resource) *Certificate {
	// Serialize the certificate to store in the S3 bucket
	return &Certificate{
		Certificate: cert.Certificate,
		PrivateKey:  cert.PrivateKey,
		Domain:      cert.Domain,
	}
}
