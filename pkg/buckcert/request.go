package buckcert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

// RequestCertWithKey obtains a certificate for domains using the provided PEM-encoded private key.
// The key is used to build a CSR so the issued certificate matches a pre-published TLSA record.
func (b *Buckcert) RequestCertWithKey(domains []string, keyPEM []byte) (*certificate.Resource, error) {
	provider, err := legoS3.NewHTTPProvider(b.config.ChallengeBucket)
	if err != nil {
		return nil, fmt.Errorf("create S3 HTTP-01 provider: %w", err)
	}
	return b.requestCertWithKeyAndProvider(domains, keyPEM, provider)
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

func (b *Buckcert) requestCertWithKeyAndProvider(domains []string, keyPEM []byte, provider challenge.Provider) (*certificate.Resource, error) {
	if err := b.client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, fmt.Errorf("set HTTP-01 provider: %w", err)
	}

	privateKey, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	csr, err := buildCSR(domains, privateKey)
	if err != nil {
		return nil, fmt.Errorf("build CSR: %w", err)
	}

	cert, err := b.client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:        csr,
		PrivateKey: privateKey,
		Bundle:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("obtain certificate for %v: %w", domains, err)
	}
	if len(cert.PrivateKey) == 0 {
		cert.PrivateKey = keyPEM
	}
	return cert, nil
}

func buildCSR(domains []string, key crypto.PrivateKey) (*x509.CertificateRequest, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain required")
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(csrBytes)
}

func parsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}
