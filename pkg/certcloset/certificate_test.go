package certcloset

import (
	"testing"

	"github.com/go-acme/lego/v4/certificate"
)

func TestValidateMissingDomain(t *testing.T) {
	c := &Certificate{Certificate: []byte("CERT")}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing domain")
	}
}

func TestValidateMissingCertificate(t *testing.T) {
	c := &Certificate{Domain: "example.com"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing certificate bytes")
	}
}

func TestValidateOK(t *testing.T) {
	c := &Certificate{Domain: "example.com", Certificate: []byte("CERT")}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSerializeCert(t *testing.T) {
	res := certificate.Resource{
		Domain:      "example.com",
		Certificate: []byte("CERT-PEM"),
		PrivateKey:  []byte("KEY-PEM"),
	}
	got := serializeCert(res)
	if got.Domain != "example.com" {
		t.Errorf("domain want %q got %q", "example.com", got.Domain)
	}
	if string(got.Certificate) != "CERT-PEM" {
		t.Errorf("cert mismatch")
	}
	if string(got.PrivateKey) != "KEY-PEM" {
		t.Errorf("key mismatch")
	}
}
