package app

import (
	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
)

type Config struct {
	Debug    bool              `help:"Enable debug mode." env:"DEBUG" default:"false"`
	LokiURL  string            `help:"Loki push URL (e.g. http://loki:3100). Disabled if empty." env:"LOKI_URL" default:""`
	LokiApp  string            `help:"Value for the 'app' label sent to Loki." env:"LOKI_APP" default:"tas3"`
	Closet   certcloset.Config `embed:"" prefix:"closet."`
}

type RenewConfig struct {
	Buckcert              buckcert.Config         `embed:"" prefix:"letsencrypt."`
	Domains               []string                `env:"DOMAINS" help:"List of domains to manage. Will be appended with traefik and redis domains."`
	IgnoredDomains        []string                `env:"IGNORED_DOMAINS" help:"List of ignored domains."`
	Traefik               traefikclient.ApiConfig `embed:"" prefix:"traefik." help:"Traefik configuration."`
	StateDir              string                  `env:"TAS3_STATE_DIR" default:"" help:"Directory to persist failure backoff state (optional). If set, domains that failed renewal are skipped for FailureBackoffMinutes."`
	FailureBackoffMinutes int                     `env:"TAS3_FAILURE_BACKOFF_MINUTES" default:"60" help:"Minutes to skip a domain after a renewal failure (avoids spamming ACME API when run every 5 min)."`
	RequestDelaySeconds   int                     `env:"TAS3_REQUEST_DELAY_SECONDS" default:"3" help:"Delay in seconds between each certificate request to avoid rate limiting."`
}

type SyncConfig struct {
	Traefik struct {
		LocalStore     string `env:"TRAEFIK_LOCAL_STORE" required:"" help:"Where to store the certificates."`
		ConfigFile     string `env:"TRAEFIK_OUTPUT_FILE" required:"" help:"The traefik configuration filename dynamically generated that will contains all the certificates definitions."`
		Format         string `env:"TRAEFIK_OUTPUT_FORMAT" required:"" default:"toml" help:"The format to store the outputed configuration."`
		CertificateDir string `env:"TRAEFIK_CERTIFICATE_DIR" required:"" help:"Where the certificates are stored relative to traefik."`
	} `embed:"" prefix:"traefik." help:"Traefik configuration."`
}
