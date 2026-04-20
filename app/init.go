package app

import (
	"io"
	"os"

	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
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
	bc, err := buckcert.NewBuckcert(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to initialize Buckcert (S3-backed ACME client)")
	}
	a.buckcert = bc

	log.Debug().Msg("Buckcert initialized")
}

func (a *App) initTraefikClient(cfg traefikclient.ApiConfig) {
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

	log.Debug().Msg("Cert closet initialized")
}
