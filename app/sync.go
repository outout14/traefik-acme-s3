package app

import (
	"os"
	"path/filepath"

	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/rs/zerolog/log"
)

func (a *App) writeCertificate(basepath string, cert *certcloset.Certificate) error {
	if err := os.MkdirAll(filepath.Join(basepath, cert.Domain), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(basepath, cert.Domain, "cert.pem"), cert.Certificate, 0644); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(basepath, cert.Domain, "key.pem"), cert.PrivateKey, 0600); err != nil {
		return err
	}

	return nil
}

func (a *App) Sync(cfg SyncConfig) error {
	localCloset, err := certcloset.NewLocalCertCloset(a.config.Closet, cfg.Traefik.CertificateDir)
	if err != nil {
		return err
	}
	localIdx := localCloset.GetIndex()
	icFailed := localCloset.CheckIntegrity()

	for _, cert := range icFailed {
		log.Error().Str("domain", cert.Domain).Msg("Certificate file missing, it will be retrieved back from remote storage")
		localIdx.Remove(cert.Domain)
	}

	diff := a.closet.GetIndex().GetDiff(localIdx)
	if len(diff) == 0 {
		log.Info().Msg("No difference between remote and local indexes, not syncing")
		return nil
	}

	for _, crt := range diff {
		log.Info().Str("domain", crt.Domain).Msg("Syncing certificate")
		cert, err := a.closet.RetrieveCertificate(crt.Domain)
		if err != nil {
			log.Error().Err(err).Str("domain", crt.Domain).Msg("Unable to retrieve certificate")
			continue
		}

		err = a.writeCertificate(cfg.Traefik.CertificateDir, cert)
		if err != nil {
			log.Error().Err(err).Str("domain", cert.Domain).Msg("Unable to store certificate")
		}
		log.Info().Str("domain", crt.Domain).Msg("Certificate synced")
	}

	localCloset.SetIndex(a.closet.GetIndex())
	return localCloset.SaveIndex()
}
