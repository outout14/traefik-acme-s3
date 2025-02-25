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
	ChallengeBucket string `env:"LETSENCRYPT_BUCKET" required:"" help:"S3 bucket to use to store the challenges."`
}

type Buckcert struct {
	/* Simple Go-ACME client with http-01 validation using the S3 bucket client */
	config Config
	bucket string // S3 bucket name
	user   *leUser
	client *lego.Client
}

func NewBuckcert(config Config) (*Buckcert, error) {
	user, err := CreateUser(config.Email)
	if err != nil {
		return nil, err
	}

	buckcert := &Buckcert{
		user:   user,
		config: config,
		bucket: config.ChallengeBucket,
	}
	if err := buckcert.genLeConfig(); err != nil {
		return nil, err
	}

	if err := buckcert.register(); err != nil {
		return nil, err
	}

	return buckcert, nil
}

func (c *Buckcert) genLeConfig() error {
	config := lego.NewConfig(c.user)

	config.CADirURL = c.config.CaURL
	config.Certificate.KeyType = certcrypto.EC256

	var err error
	c.client, err = lego.NewClient(config)
	return err
}

func (c *Buckcert) register() error {
	reg, err := c.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("unable to register: %w", err)
	}
	c.user.Registration = reg

	return nil
}
