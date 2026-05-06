package app

import (
	"github.com/go-acme/lego/v4/certificate"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/lokiwriter"
)

// certStore is the interface App uses for certificate storage.
type certStore interface {
	GetIndex() *certcloset.CertificateList
	SaveIndex() error
	StoreCertificate(cert certificate.Resource) error
	RetrieveCertificate(domain string) (*certcloset.Certificate, error)
	CertificateExists(domain string) (bool, error)
}

// certRequester is the interface App uses to obtain ACME certificates.
type certRequester interface {
	RequestCert(domains []string) (*certificate.Resource, error)
}

// domainProvider is the interface App uses to list domains from Traefik.
type domainProvider interface {
	GetDomains() ([]string, error)
}

type App struct {
	buckcert   certRequester
	closet     certStore
	traefikApi domainProvider
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
