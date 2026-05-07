package app

import (
	"sync"
	"time"

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
	RemoveFromIndex(domain string)
}

// stateStore is the interface App uses for failure/rollover state and distributed locking.
type stateStore interface {
	AcquireLock() error
	ReleaseLock()
	LoadFailureState() (*certcloset.FailureState, error)
	StoreFailureState(*certcloset.FailureState) error
	LoadRolloverState(domain string) (*certcloset.RolloverState, bool, error)
	StoreRolloverState(domain string, state *certcloset.RolloverState) error
	DeleteRolloverState(domain string) error
	StorePendingKey(domain string, keyPEM []byte) error
	LoadPendingKey(domain string) ([]byte, error)
	DeletePendingKey(domain string) error
}

// certRequester is the interface App uses to obtain ACME certificates.
type certRequester interface {
	RequestCert(domains []string) (*certificate.Resource, error)
	RequestCertWithKey(domains []string, keyPEM []byte) (*certificate.Resource, error)
}

// domainProvider is the interface App uses to list domains from Traefik.
type domainProvider interface {
	GetDomains() ([]string, error)
}

// dnsUpdater is the interface App uses to push DNS records after certificate renewal.
type dnsUpdater interface {
	UpdateDNS(domain string, certPEM []byte) error
	AddTLSA(domain, tlsaHex string) error
	RemoveTLSA(domain, tlsaHex string) error
	UpdateCAA(domain string) error
	Enabled(domain string) bool
}

type App struct {
	buckcert   certRequester
	closet     certStore
	state      stateStore
	traefikApi domainProvider
	lokiWriter *lokiwriter.Writer
	dnsUpdate  dnsUpdater
	metrics    *appMetrics
	config     Config

	mu        sync.Mutex // protects lastRenew / lastSync
	lastRenew time.Time
	lastSync  time.Time
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
	a.metrics = newAppMetrics()
}
