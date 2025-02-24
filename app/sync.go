package app

import (
	"crypto/x509"
)

type certStore struct {
	Certificates map[string]*x509.Certificate
}

func (a *App) Sync(cfg SyncConfig) error {
	return nil
}
