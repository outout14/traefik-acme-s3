package app

import (
	"os"

	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func (a *App) initLog() {
	// Configure timestamp + console formatting
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Enable debug if needed
	if a.config.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug mode enabled")
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
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
