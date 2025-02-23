package app

import (
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/rs/zerolog/log"
)

type App struct {
	config   Config
	s3       *s3.Client
	buckcert *buckcert.Buckcert
	closet   *certcloset.CertCloset
}

func (a *App) Init(config Config) {
	a.config = config
	a.initLog()
	a.initS3()
	a.initCloset()
	a.initBuckcert()

	if a.config.Traefik.ApiURL != "" {
		a.loadDomains()
	} else {
		log.Warn().Msg("No Traefik API URL provided, skipping domain loading")
	}
	log.Debug().Strs("domains", a.config.Domains).Msg("Domains loaded")

}
