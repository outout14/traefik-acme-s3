package dnsupdate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// GenerateTLSA returns the DANE-EE SPKI SHA-256 hex string for a certificate
// (usage 3, selector 1, matching type 1).
func GenerateTLSA(cert *x509.Certificate) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal SPKI: %w", err)
	}
	digest := sha256.Sum256(spki)
	return hex.EncodeToString(digest[:]), nil
}

// GenerateKeyAndTLSA generates a new EC P-256 private key and returns its PEM encoding
// alongside the DANE-EE SPKI SHA-256 hex that must be pre-published in DNS before the
// certificate is requested with that key.
func GenerateKeyAndTLSA() (keyPEM []byte, tlsaHex string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate EC key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("marshal EC key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshal SPKI: %w", err)
	}
	digest := sha256.Sum256(spki)
	return keyPEM, hex.EncodeToString(digest[:]), nil
}

// TLSAHexFromCertPEM returns the DANE-EE SPKI SHA-256 hex for a PEM-encoded certificate.
func TLSAHexFromCertPEM(certPEM []byte) (string, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return "", err
	}
	return GenerateTLSA(cert)
}
