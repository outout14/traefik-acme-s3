package app

import (
	"fmt"

	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/rs/zerolog/log"
)

func (a *App) Sync(cfg SyncConfig) error {
	localCloset, err := certcloset.NewLocalCertCloset(a.config.Closet, cfg.Traefik.CertificateDir)
	if err != nil {
		return err
	}
	localIdx := localCloset.GetIndex()

	icFailed := localCloset.IntegrityCheck()
	for _, cert := range icFailed {
		log.Error().Str("domain", cert.Domain).Msg("Certificate file missing")
		localIdx.Remove(cert.Domain)
	}

	remoteIdx := a.closet.GetIndex()
	diff := remoteIdx.GetDiff(localIdx)
	if len(diff) == 0 {
		log.Info().Msg("No difference between remote and local indexes, not syncing")
		return nil
	}

	for _, cert := range diff {
		fmt.Println(cert)
	}

	return err
}
