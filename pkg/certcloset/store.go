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
	cert.PrivateKey, err = c.encryptPrivKey(cert)

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
