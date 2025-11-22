package buckcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
)

type leUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *leUser) GetEmail() string {
	return u.Email
}

func (u *leUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *leUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// CreateUser creates an ACME user with a new private key.
// The key type is configurable through your config (P256, P384, RSA2048, etc.)
func CreateUser(email string) (*leUser, error) {
	// Default to P256 to match your defaults
	privateKey, err := generateKey(certcrypto.EC256)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %w", err)
	}

	return &leUser{
		Email: email,
		key:   privateKey,
	}, nil
}

// generateKey generates a private key from a lego certcrypto.KeyType.
// This allows you to support P256, P384, RSA2048, RSA4096, ...
func generateKey(k certcrypto.KeyType) (crypto.PrivateKey, error) {
	switch k {
	case certcrypto.EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case certcrypto.EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case certcrypto.RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case certcrypto.RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case certcrypto.RSA8192:
		return rsa.GenerateKey(rand.Reader, 8192)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k)
	}
}
