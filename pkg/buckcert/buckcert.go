package buckcert

import (
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type Config struct {
	Email           string `env:"LETSENCRYPT_EMAIL" required:"" help:"Email to use for the Let's Encrypt account."`
	CaURL           string `env:"LETSENCRYPT_CA_URL" required:"" default:"https://acme-staging-v02.api.letsencrypt.org/directory" help:"Let's Encrypt CA URL to use."`
	KeyType         string `env:"LETSENCRYPT_KEY_TYPE" required:"" default:"P256" help:"Let's Encrypt key type to use."`
	ChallengeBucket string `env:"LETSENCRYPT_BUCKET" required:"" help:"S3 bucket to use for HTTP-01 challenge files."`
}

type Buckcert struct {
	config Config
	bucket string
	user   *leUser
	client *lego.Client
}

func NewBuckcert(cfg Config) (*Buckcert, error) {
	user, err := CreateUser(cfg.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME user: %w", err)
	}

	b := &Buckcert{
		user:   user,
		config: cfg,
		bucket: cfg.ChallengeBucket,
	}

	if err := b.initClient(); err != nil {
		return nil, err
	}

	if err := b.register(); err != nil {
		return nil, err
	}

	return b, nil
}

// initClient builds the Lego client using the configured CA, key type, and user.
func (b *Buckcert) initClient() error {
	legoCfg := lego.NewConfig(b.user)
	legoCfg.CADirURL = b.config.CaURL

	keyType, err := parseKeyType(b.config.KeyType)
	if err != nil {
		return fmt.Errorf("invalid key type %q: %w", b.config.KeyType, err)
	}

	legoCfg.Certificate.KeyType = keyType

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	b.client = client
	return nil
}

func (b *Buckcert) register() error {
	reg, err := b.client.Registration.Register(
		registration.RegisterOptions{TermsOfServiceAgreed: true},
	)
	if err != nil {
		return fmt.Errorf("ACME registration failed: %w", err)
	}

	b.user.Registration = reg
	return nil
}

// parseKeyType converts "P256" / "P384" / "RSA2048" etc. into a lego certcrypto.KeyType.
func parseKeyType(s string) (certcrypto.KeyType, error) {
	switch s {
	case "P256":
		return certcrypto.EC256, nil
	case "P384":
		return certcrypto.EC384, nil
	case "RSA2048":
		return certcrypto.RSA2048, nil
	case "RSA4096":
		return certcrypto.RSA4096, nil
	case "RSA8192":
		return certcrypto.RSA8192, nil
	default:
		return "", fmt.Errorf("unknown key type")
	}
}
