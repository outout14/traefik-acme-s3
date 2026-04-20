package app

import (
	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/lokiwriter"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
)

type App struct {
	buckcert   *buckcert.Buckcert
	closet     *certcloset.CertCloset
	traefikApi *traefikclient.ApiClient
	lokiWriter *lokiwriter.Writer
	config     Config
}

// Close flushes the Loki writer if active. Call after Renew/Sync completes.
func (a *App) Close() {
	if a.lokiWriter != nil {
		a.lokiWriter.Close()
	}
}

func (a *App) Init(config Config) {
	a.config = config
	a.initLog()
	a.initCertCloset()
}
