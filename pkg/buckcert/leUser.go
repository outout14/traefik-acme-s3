package buckcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
	"github.com/rs/zerolog/log"
)

type leUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          []byte                 `json:"key"` // PEM-encoded
}

// UserStore persists the ACME account user JSON. CertCloset implements this
// with encrypted S3 storage.
type UserStore interface {
	LoadACMEUser() (data []byte, exists bool, err error)
	StoreACMEUser(data []byte) error
	StoreACMEUserIfNotExists(data []byte) (stored bool, err error)
}

func (u *leUser) GetEmail() string {
	return u.Email
}

func (u *leUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *leUser) GetPrivateKey() crypto.PrivateKey {
	key, err := certcrypto.ParsePEMPrivateKey(u.Key)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse ACME user private key")
	}
	return key
}

func marshalUser(u *leUser) ([]byte, error) {
	return json.MarshalIndent(u, "", "  ")
}

func parseUser(data []byte) (*leUser, error) {
	var u leUser
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, err
	}
	if u.Email == "" {
		return nil, fmt.Errorf("missing ACME user email")
	}
	if len(u.Key) == 0 {
		return nil, fmt.Errorf("missing ACME user private key")
	}
	if _, err := certcrypto.ParsePEMPrivateKey(u.Key); err != nil {
		return nil, fmt.Errorf("invalid ACME user private key: %w", err)
	}

	return &u, nil
}

func SaveUser(u *leUser, path string) error {
	data, err := marshalUser(u)
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

	return parseUser(data)
}

func newUser(email string) (*leUser, error) {
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

// CreateUser creates or loads a local ACME user. It is kept for legacy file
// storage and tests; production App wiring uses LoadOrCreateUser with S3 storage.
func CreateUser(email, path string) (*leUser, error) {
	log.Debug().Str("path", path).Msg("trying to load ACME user")
	u, err := LoadUser(path)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load ACME user: %w", err)
	}

	log.Info().Msg("no existing ACME user found, creating a new one")
	return newUser(email)
}

// LoadOrCreateUser returns the ACME user from encrypted S3 storage when a
// UserStore is configured. If S3 is empty, it imports a valid local user file or
// creates a new user, then stores it in S3 using a create-if-absent write.
func LoadOrCreateUser(cfg Config) (*leUser, error) {
	if cfg.UserStore == nil {
		return CreateUser(cfg.Email, cfg.UserKeyPath)
	}

	data, exists, err := cfg.UserStore.LoadACMEUser()
	if err != nil {
		return nil, fmt.Errorf("load ACME user from S3: %w", err)
	}
	if exists {
		u, err := parseUser(data)
		if err != nil {
			return nil, fmt.Errorf("parse S3 ACME user: %w", err)
		}
		log.Info().Msg("loaded ACME user from encrypted S3 storage")
		return u, nil
	}

	user, source, err := loadLocalOrNewUser(cfg.Email, cfg.UserKeyPath)
	if err != nil {
		return nil, err
	}
	data, err = marshalUser(user)
	if err != nil {
		return nil, err
	}
	stored, err := cfg.UserStore.StoreACMEUserIfNotExists(data)
	if err != nil {
		return nil, fmt.Errorf("store ACME user in S3: %w", err)
	}
	if stored {
		log.Info().Str("source", source).Msg("stored ACME user in encrypted S3 storage")
		return user, nil
	}

	data, exists, err = cfg.UserStore.LoadACMEUser()
	if err != nil {
		return nil, fmt.Errorf("reload concurrently-created ACME user from S3: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("ACME user was created concurrently but is not readable from S3")
	}
	user, err = parseUser(data)
	if err != nil {
		return nil, fmt.Errorf("parse concurrently-created S3 ACME user: %w", err)
	}
	log.Info().Msg("loaded ACME user created by another instance")
	return user, nil
}

func loadLocalOrNewUser(email, path string) (*leUser, string, error) {
	if path != "" {
		u, err := LoadUser(path)
		if err == nil {
			log.Info().Str("path", path).Msg("importing local ACME user into encrypted S3 storage")
			return u, "local-file", nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("load local ACME user for S3 import: %w", err)
		}
	}

	log.Info().Msg("no existing ACME user found in S3 or local storage, creating a new one")
	u, err := newUser(email)
	if err != nil {
		return nil, "", err
	}
	return u, "new", nil
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
