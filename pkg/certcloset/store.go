package certcloset

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-acme/lego/v4/certificate"
)

// expiryFromCertPEM parses the leaf cert in certPEM and returns its NotAfter.
// Falls back to 89 days from now when the PEM cannot be parsed.
func expiryFromCertPEM(certPEM []byte) time.Time {
	block, _ := pem.Decode(certPEM)
	if block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return cert.NotAfter
		}
	}
	return time.Now().AddDate(0, 0, 89)
}

// IsErrNotFound returns true if the error indicates the S3 object does not exist (404).
func IsErrNotFound(err error) bool {
	return isErrHTTPStatus(err, http.StatusNotFound)
}

func isErrHTTPStatus(err error, status int) bool {
	var responseError *awshttp.ResponseError
	return errors.As(err, &responseError) && responseError.ResponseError.HTTPStatusCode() == status
}

// StoreCertificate serializes a certificate.Resource and stores it in
// the configured S3 bucket. If PushPrivateKey is enabled the private
// key is encrypted before storage. The function also updates the in-
// memory index with the certificate's expiration date.
func (c *CertCloset) StoreCertificate(cert certificate.Resource) error {
	var err error

	if c.config.PushPrivateKey {
		cert.PrivateKey, err = c.encryptPrivKey(cert)
	} else {
		cert.PrivateKey = nil
	}

	if err != nil {
		return fmt.Errorf("unable to get the private key bytes: %w", err)
	}

	serialized := serializeCert(cert)

	jsonCert, err := json.Marshal(serialized)
	if err != nil {
		return err
	}

	if err = c.s3PutWithRetry(cert.Domain, jsonCert); err != nil {
		return fmt.Errorf("unable to store certificate in S3 after retries: %w", err)
	}

	// Update the index — use actual cert expiry, fall back to 89 days if PEM unparseable.
	expDate := expiryFromCertPEM(cert.Certificate)

	c.mu.Lock()
	c.index.CertIndex[cert.Domain] = CertificateEntry{
		Domain:         cert.Domain,
		ExpirationDate: expDate,
	}
	c.dirty = true
	c.mu.Unlock()

	return nil
}

// RetrieveCertificate fetches the certificate JSON from S3 for the
// given domain, decodes it, optionally decrypts the private key and
// returns a Certificate object or an error.
func (c *CertCloset) RetrieveCertificate(domain string) (*Certificate, error) {
	// Retrieve the certificate from the S3 bucket
	s3cert, err := c.s3.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &domain,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve certificate from S3: %w", err)
	}
	defer s3cert.Body.Close()

	// Unmarshal the certificate
	var cert Certificate
	err = json.NewDecoder(s3cert.Body).Decode(&cert)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal certificate: %w", err)
	}
	cert.Domain = domain // As the domain is not stored in the JSON

	if err := cert.Validate(); err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	if c.config.PushPrivateKey {
		cert.PrivateKey, err = c.decryptPrivKey(cert.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt the private key: %w", err)
		}
	}

	return &cert, nil
}

// CertificateExists returns true if the certificate object exists in S3 for the given domain.
// Returns (false, nil) when the object is not found (404); (false, err) for other errors.
func (c *CertCloset) CertificateExists(domain string) (bool, error) {
	_, err := c.s3.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &domain,
	})
	if err != nil {
		if IsErrNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
