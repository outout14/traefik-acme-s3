package buckcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
)

type leUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          []byte                 `json:"key"` // PEM-encoded
}

func (u *leUser) GetEmail() string {
	return u.Email
}

func (u *leUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *leUser) GetPrivateKey() crypto.PrivateKey {
	key, _ := certcrypto.ParsePEMPrivateKey(u.Key)
	return key
}

func SaveUser(u *leUser, path string) error {
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func LoadUser(path string) (*leUser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var u leUser
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, err
	}

	return &u, nil
}

// CreateUser creates an ACME user with a new private key.
// The key type is configurable through your config (P256, P384, RSA2048, etc.)
func CreateUser(email, path string) (*leUser, error) {
	// Try loading existing user
	fmt.Println("trying to load user from", path)
	if u, err := LoadUser(path); err == nil {
		return u, nil
	}

	fmt.Println("no existing user found, creating a new one")

	// Otherwise create a new one
	privateKey, err := generateKey(certcrypto.EC256)
	if err != nil {
		return nil, err
	}

	keyPEM := certcrypto.PEMEncode(privateKey)

	user := &leUser{
		Email: email,
		Key:   keyPEM,
	}
	return user, nil
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
