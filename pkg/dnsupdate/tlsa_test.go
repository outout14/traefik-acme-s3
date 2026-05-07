package dnsupdate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

func makeSelfSignedCert(t *testing.T, pub, priv any, cn string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func expectedTLSA(t *testing.T, pub any) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	digest := sha256.Sum256(spki)
	return hex.EncodeToString(digest[:])
}

func TestGenerateTLSA_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeSelfSignedCert(t, &key.PublicKey, key, "ec.example.com")
	want := expectedTLSA(t, &key.PublicKey)

	got, err := GenerateTLSA(cert)
	if err != nil {
		t.Fatalf("GenerateTLSA: %v", err)
	}
	if got != want {
		t.Errorf("TLSA hex mismatch\n  got  %s\n  want %s", got, want)
	}
}

func TestGenerateTLSA_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeSelfSignedCert(t, &key.PublicKey, key, "rsa.example.com")
	want := expectedTLSA(t, &key.PublicKey)

	got, err := GenerateTLSA(cert)
	if err != nil {
		t.Fatalf("GenerateTLSA: %v", err)
	}
	if got != want {
		t.Errorf("TLSA hex mismatch\n  got  %s\n  want %s", got, want)
	}
}

func TestGenerateTLSA_DifferentKeys(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	cert1 := makeSelfSignedCert(t, &key1.PublicKey, key1, "a.example.com")
	cert2 := makeSelfSignedCert(t, &key2.PublicKey, key2, "b.example.com")

	hex1, err := GenerateTLSA(cert1)
	if err != nil {
		t.Fatal(err)
	}
	hex2, err := GenerateTLSA(cert2)
	if err != nil {
		t.Fatal(err)
	}
	if hex1 == hex2 {
		t.Error("distinct keys must produce distinct TLSA hashes")
	}
}
