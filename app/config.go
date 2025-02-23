package app

import (
	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/rs/zerolog/log"
)

type Config struct {
	Debug   bool   `help:"Enable debug mode." env:"DEBUG"`
	Bucket  string `env:"S3_BUCKET" required:"" prefix:"s3." help:"S3 bucket to use to store the GENERATED CERTIFICATES."`
	Traefik struct {
		OutputDir      string `env:"TRAEFIK_OUTPUT_DIR" default:"/etc/traefik/acme" help:"Traefik output directory to output the certificate configuration files."`
		CertificateDir string `env:"TRAEFIK_CERTIFICATE_DIR" default:"/etc/traefik/certs" help:"Traefik certificate directory to output the certificate files."`
		ApiURL         string `env:"TRAEFIK_API_URL" help:"Traefik API URL to use to retrieve the domains."`
		ApiUsername    string `env:"TRAEFIK_API_USERNAME" default:"" help:"Traefik API username to use to retrieve the domains."`
		ApiPassword    string `env:"TRAEFIK_API_PASSWORD" default:"" help:"Traefik API password to use to retrieve the domains."`
	} `embed:"" prefix:"traefik."`
	Letsencrypt buckcert.Config   `embed:"" prefix:"letsencrypt."`
	Closet      certcloset.Config `embed:"" prefix:"closet."`
	Domains     []string          `env:"DOMAINS" help:"List of domains to manage. Will be appended with traefik and redis domains."`
}

func (c *Config) Validate() error {
	if c.Letsencrypt.ChallengeBucket == "" {
		c.Letsencrypt.ChallengeBucket = c.Bucket
		log.Warn().Str("bucket", c.Bucket).Msg("No LETSENCRYPT_BUCKET provided, using S3_BUCKET")
	}

	if c.Traefik.ApiURL == "" {
		log.Warn().Msg("No TRAEFIK_API_URL provided, skipping domain loading")
	}

	if len(c.Closet.Password) != 32 {
		log.Warn().Str("password", c.Closet.Password).Msg("Password should be 32 characters long")
	}

	return nil
}
