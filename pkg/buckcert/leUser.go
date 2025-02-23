package buckcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

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
func (u leUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *leUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func CreateUser(email string) (*leUser, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // TODO : use the key size from the config
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %w", err)
	}

	return &leUser{
		Email: email,
		key:   privateKey,
	}, nil
}
