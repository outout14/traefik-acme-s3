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
	Traefik traefikclient.LocalConfig `embed:"" prefix:"traefik." help:"Traefik configuration."`
}
