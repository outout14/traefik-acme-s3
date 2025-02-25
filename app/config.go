package app

import (
	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
)

type Config struct {
	Debug  bool              `help:"Enable debug mode." env:"DEBUG"`
	Closet certcloset.Config `embed:"" prefix:"closet."`
}

type RenewConfig struct {
	Buckcert buckcert.Config         `embed:"" prefix:"letsencrypt."`
	Domains  []string                `env:"DOMAINS" help:"List of domains to manage. Will be appended with traefik and redis domains."`
	Traefik  traefikclient.ApiConfig `embed:"" prefix:"traefik." help:"Traefik configuration."`
}

type SyncConfig struct {
	Traefik struct {
		LocalStore     string `env:"TRAEFIK_LOCAL_STORE" required:"" help:"Where to store the certificates."`
		ConfigFile     string `env:"TRAEFIK_OUTPUT_FILE" required:"" help:"The traefik configuration filename dynamically generated that will contains all the certificates definitions."`
		Format         string `env:"TRAEFIK_OUTPUT_FORMAT" required:"" default:"toml" help:"The format to store the outputed configuration."`
		CertificateDir string `env:"TRAEFIK_CERTIFICATE_DIR" required:"" help:"Where the certificates are stored relative to traefik."`
	} `embed:"" prefix:"traefik." help:"Traefik configuration."`
}
