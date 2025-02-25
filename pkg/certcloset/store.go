package certcloset

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-acme/lego/v4/certificate"
)

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

	// Store the certificate in the S3 bucket
	_, err = c.s3.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &cert.Domain,
		Body:   bytes.NewReader(jsonCert),
	})
	if err != nil {
		return fmt.Errorf("unable to store certificate in S3: %w", err)
	}

	// Update the index
	// expDate is today + 89 days (the max validity of a Let's Encrypt certificate)
	expDate := time.Now().AddDate(0, 0, 89)

	c.index.CertIndex[cert.Domain] = CertificateEntry{
		Domain:         cert.Domain,
		ExpirationDate: expDate,
	}

	return nil
}

func (c *CertCloset) RetrieveCertificate(domain string) (*Certificate, error) {
	// Retrieve the certificate from the S3 bucket
	s3cert, err := c.s3.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &domain,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve certificate from S3: %w", err)
	}

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
