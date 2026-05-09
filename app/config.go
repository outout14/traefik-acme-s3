package app

import (
	"fmt"
	"net"
	"time"

	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/configserverclient"
	"github.com/outout14/traefik-acme-s3/pkg/dnsupdate"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
)

type Config struct {
	Debug  bool              `help:"Enable debug mode." env:"DEBUG" default:"false"`
	Closet certcloset.Config `embed:"" prefix:"closet."`
}

// DaemonConfig holds interval and HTTP trigger settings shared by renew and sync daemon modes.
// TAS3_INTERVAL=0 (default) means run once and exit. Both daemon types use the same env var
// names since they run as separate processes.
type DaemonConfig struct {
	Interval         time.Duration `env:"TAS3_INTERVAL" default:"0" help:"Run as daemon with this interval (e.g. 1h, 5m). 0 = run once and exit."`
	HTTPAddr         string        `env:"TAS3_HTTP_ADDR" default:"" help:"Bind address for HTTP trigger+health server (e.g. :8080). Bind to loopback or use a reverse proxy — no TLS is provided. Empty = disabled."`
	HTTPToken        string        `env:"TAS3_HTTP_TOKEN" default:"" help:"Bearer token for HTTP trigger auth. Takes priority over TAS3_HTTP_TOKEN_FILE."`
	HTTPTokenFile    string        `env:"TAS3_HTTP_TOKEN_FILE" default:"" help:"Path to file containing the HTTP trigger token (Docker secret fallback)."`
	TriggerRateLimit int           `env:"TAS3_TRIGGER_RATE_LIMIT" default:"10" help:"Max POST /trigger requests per minute (0 = unlimited)."`
	MetricsAddr      string        `env:"TAS3_METRICS_ADDR" default:"" help:"Separate bind address for /metrics endpoint (e.g. :9090). Empty = serve on HTTPAddr if set."`
}

// Validate returns an error for invalid DaemonConfig combinations.
func (d *DaemonConfig) Validate() error {
	if d.Interval <= 0 {
		return fmt.Errorf("TAS3_INTERVAL must be positive for daemon mode (got %v)", d.Interval)
	}
	return nil
}

// isLoopback reports whether the host part of addr resolves to a loopback interface.
// Empty host (":8080") means bind-all and is NOT considered loopback.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type RenewConfig struct {
	Buckcert              buckcert.Config           `embed:"" prefix:"letsencrypt."`
	Domains               []string                  `env:"DOMAINS" help:"List of domains to manage. Will be appended with traefik and redis domains."`
	IgnoredDomains        []string                  `env:"IGNORED_DOMAINS" help:"List of ignored domains."`
	Traefik               traefikclient.ApiConfig   `embed:"" prefix:"traefik." help:"Traefik configuration."`
	ConfigServer          configserverclient.Config `embed:"" prefix:"config-server." help:"Config-server domain source (optional)."`
	DNSUpdate             dnsupdate.Config          `embed:"" prefix:"dns-update."`
	FailureBackoffMinutes int                       `env:"TAS3_FAILURE_BACKOFF_MINUTES" default:"60" help:"Minutes to skip a domain after a renewal failure (avoids spamming ACME API when run every 5 min)."`
	ForceRenewOnFailure   bool                      `env:"TAS3_FORCE_RENEW_ON_FAILURE" default:"false" help:"If true, ignore failure backoff and force renewal attempts even for recently failed domains."`
	RequestDelaySeconds   int                       `env:"TAS3_REQUEST_DELAY_SECONDS" default:"3" help:"Delay in seconds between each certificate request to avoid rate limiting."`
	DaemonConfig          `embed:""`
}

type SyncConfig struct {
	Traefik struct {
		LocalStore     string `env:"TRAEFIK_LOCAL_STORE" required:"" help:"Where to store the certificates (also used as local cert cache for HAProxy sync)."`
		ConfigFile     string `env:"TRAEFIK_OUTPUT_FILE" default:"" help:"Traefik dynamic config file to generate. Empty = Traefik config not written."`
		Format         string `env:"TRAEFIK_OUTPUT_FORMAT" default:"toml" help:"Format for the Traefik config file (toml or yaml)."`
		CertificateDir string `env:"TRAEFIK_CERTIFICATE_DIR" default:"" help:"Cert dir as Traefik sees it (for config file paths). Required when TRAEFIK_OUTPUT_FILE is set."`
	} `embed:"" prefix:"traefik." help:"Traefik configuration."`
	HAProxy struct {
		CertDir     string `env:"HAPROXY_CRT_DIR" default:"" help:"Directory where HAProxy PEM bundles (cert+key) are written. Empty = HAProxy sync disabled."`
		CrtListFile string `env:"HAPROXY_CRT_LIST_FILE" default:"" help:"Path to HAProxy crt-list file to generate. Empty = no crt-list written."`
		CertDirRef  string `env:"HAPROXY_CRT_DIR_REF" default:"" help:"Cert dir as HAProxy sees it in crt-list paths. Defaults to HAPROXY_CRT_DIR if empty."`
	} `embed:"" prefix:"haproxy." help:"HAProxy configuration (optional)."`
	DaemonConfig `embed:""`
}
