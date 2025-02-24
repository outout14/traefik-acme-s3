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
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if a.config.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Debug().Msg("Debug mode enabled")
}

func (a *App) initBuckcert(le buckcert.Config) {
	var err error
	a.buckcert, err = buckcert.NewBuckcert(le)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create the letsencrypt client for the S3 bucket")
	}
	log.Debug().Msg("Buckcert initialized")
}

func (a *App) initTraefikClient(cfg traefikclient.ApiConfig) {
	var err error
	a.traefikApi, err = traefikclient.NewTraefikApiClient(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create the traefik client")
	}
	log.Debug().Msg("TraefikClient initialized")
}

func (a *App) initCertCloset() {
	var err error
	a.closet, err = certcloset.NewCertCloset(a.config.Closet)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create cert closet")
	}
	log.Debug().Msg("CertCloset initialized")
}
