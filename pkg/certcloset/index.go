package certcloset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var CerticateIndexFile = "cert_index.json" // certificate index name on S3

type CertificateList struct {
	// The CertIndex is a JSON that contains the certificate
	CertIndex map[string]CertificateEntry `json:"cert_index"`
}

type CertificateEntry struct {
	// The expiration date of the certificate.
	Domain         string    `json:"domain"`
	ExpirationDate time.Time `json:"expiration_date"`
}

func (cl *CertificateList) GetDiff(other CertificateList) []*CertificateEntry {
	var diff []*CertificateEntry
	for k, v := range cl.CertIndex {
		if other.CertIndex[k].ExpirationDate != v.ExpirationDate {
			diff = append(diff, &CertificateEntry{
				Domain:         k,
				ExpirationDate: v.ExpirationDate,
			})
		}
	}
	return diff
}

func (c *CertCloset) RetrieveIndex() error {
	// Retrieve current index from S3
	s3idx, err := c.s3.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &CerticateIndexFile,
	})

	if err != nil {
		var responseError *awshttp.ResponseError
		if errors.As(err, &responseError) && responseError.ResponseError.HTTPStatusCode() == http.StatusNotFound {
			// -> create index
			c.index = CertificateList{
				CertIndex: make(map[string]CertificateEntry),
			}
			return nil
		}

		return err
	}

	// Decode the index
	err = json.NewDecoder(s3idx.Body).Decode(&c.index)
	if err != nil {
		return err
	}

	return nil
}

func (c *CertCloset) SaveIndex() error {
	// Save the index to S3
	idx, err := json.Marshal(c.index)
	if err != nil {
		return err
	}

	_, err = c.s3.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.config.Bucket,
		Key:    &CerticateIndexFile,
		Body:   bytes.NewReader(idx),
	})
	if err != nil {
		return err
	}

	return nil
}

func (c *CertificateList) Add(cert CertificateEntry) {
	c.CertIndex[cert.Domain] = cert
}

func (c *CertificateList) Remove(domain string) {
	delete(c.CertIndex, domain)
}
