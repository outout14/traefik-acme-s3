package app

import (
	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
)

type App struct {
	buckcert     *buckcert.Buckcert
	closet       *certcloset.CertCloset
	traefikApi   *traefikclient.ApiClient
	traefikLocal *traefikclient.LocalClient
	config       Config
}

func (a *App) Init(config Config) {
	a.config = config
	a.initLog()
	a.initCertCloset()
}
