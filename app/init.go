package app

import (
	"io"
	"os"

	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/dnsupdate"
	"github.com/outout14/traefik-acme-s3/pkg/lokiwriter"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func (a *App) initLog() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	var writers []io.Writer

	if a.config.Debug {
		writers = append(writers, zerolog.ConsoleWriter{Out: os.Stderr})
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		writers = append(writers, os.Stderr)
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if a.config.LokiURL != "" {
		lw := lokiwriter.New(a.config.LokiURL, map[string]string{
			"app": a.config.LokiApp,
		})
		a.lokiWriter = lw
		writers = append(writers, lw)
	}

	log.Logger = zerolog.New(zerolog.MultiLevelWriter(writers...)).With().Timestamp().Logger()

	if a.config.Debug {
		log.Debug().Msg("debug mode enabled")
	}
	if a.config.LokiURL != "" {
		log.Debug().Str("url", a.config.LokiURL).Msg("Loki writer active")
	}
}

func (a *App) initBuckcert(cfg buckcert.Config) {
	if a.buckcert != nil {
		return // already set (e.g. injected in tests)
	}
	if cfg.UserKeyPath == "./le_user.json" {
		log.Warn().Msg("UserKeyPath is the default './le_user.json' — ACME registration will be lost on container restart. Mount a persistent volume and set LETSENCRYPT_USER_KEY_PATH.")
	}
	bc, err := buckcert.NewBuckcert(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to initialize Buckcert (S3-backed ACME client)")
	}
	a.buckcert = bc

	log.Debug().Msg("Buckcert initialized")
}

func (a *App) initTraefikClient(cfg traefikclient.ApiConfig) {
	if a.traefikApi != nil {
		return // already set (e.g. injected in tests)
	}
	tc, err := traefikclient.NewTraefikApiClient(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to initialize Traefik API client")
	}
	a.traefikApi = tc

	log.Debug().Msg("Traefik client initialized")
}

func (a *App) initCertCloset() {
	cl, err := certcloset.NewCertCloset(a.config.Closet)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to initialize certificate closet")
	}
	a.closet = cl
	a.state = cl // CertCloset implements stateStore; S3 is single source of truth for all state

	log.Debug().Msg("Cert closet initialized")
}

func (a *App) initDNSUpdater(cfg dnsupdate.Config, caURL string) {
	if a.dnsUpdate != nil {
		return // already set (e.g. injected in tests)
	}
	if !cfg.Enabled {
		return
	}
	// Duck-type to get the ACME account URI for RFC 8657 CAA accounturi parameter.
	// Only *buckcert.Buckcert implements this; mocks and other impls return "".
	accountURI := ""
	type accountURIProvider interface{ AccountURI() string }
	if p, ok := a.buckcert.(accountURIProvider); ok {
		accountURI = p.AccountURI()
	}
	u, err := dnsupdate.New(cfg, caURL, accountURI)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to initialize DNS updater")
	}
	a.dnsUpdate = u
	log.Debug().Str("account_uri", accountURI).Msg("DNS updater initialized")
}
