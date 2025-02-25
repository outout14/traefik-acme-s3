package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/traefikclient"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

const (
	CERT_EXT = "cert.pem"
	KEY_EXT  = "key.pem"
)

func (a *App) writeCertificate(basepath string, cert *certcloset.Certificate) error {
	if err := os.MkdirAll(filepath.Join(basepath, cert.Domain), 0755); err != nil {
		return err
	}
	for path, content := range map[string][]byte{
		filepath.Join(basepath, cert.Domain, CERT_EXT): cert.Certificate,
		filepath.Join(basepath, cert.Domain, KEY_EXT):  cert.PrivateKey,
	} {
		if err := os.WriteFile(path, content, 0644); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) syncCerts(cfg SyncConfig) error {
	localCloset, err := certcloset.NewLocalCertCloset(a.config.Closet, cfg.Traefik.LocalStore)
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

		err = a.writeCertificate(cfg.Traefik.LocalStore, cert)
		if err != nil {
			log.Error().Err(err).Str("domain", cert.Domain).Msg("Unable to store certificate")
		}
		log.Info().Str("domain", crt.Domain).Msg("Certificate synced")
	}

	localCloset.SetIndex(a.closet.GetIndex())
	return localCloset.SaveIndex()
}

func (a *App) writeTraefikConfig(cfg SyncConfig) error {
	tcfg := traefikclient.TraefikRootConfig{
		Tls: traefikclient.TraefikTLS{
			Certificates: make([]traefikclient.TraefikCertificate, 0),
		},
	}

	for domain := range a.closet.GetIndex().CertIndex {
		tcfg.Tls.Certificates = append(tcfg.Tls.Certificates, traefikclient.TraefikCertificate{
			CertFile: filepath.Join(cfg.Traefik.CertificateDir, domain, CERT_EXT),
			KeyFile:  filepath.Join(cfg.Traefik.CertificateDir, domain, KEY_EXT),
		})
	}

	var out []byte
	var err error
	if cfg.Traefik.Format == "toml" {
		out, err = toml.Marshal(tcfg)
		if err != nil {
			log.Error().Err(err).Msg("Unable to marshal certificate pair")
			return err
		}
	} else if cfg.Traefik.Format == "yaml" {
		out, err = yaml.Marshal(tcfg)
		if err != nil {
			log.Error().Err(err).Msg("Unable to marshal certificate pair")
			return err
		}
	} else {
		log.Fatal().Str("format", cfg.Traefik.Format).Msg("Unsupported format for traefik configuration")
		return fmt.Errorf("unsupported format for traefik configuration: %s", cfg.Traefik.Format)
	}

	if err := os.WriteFile(cfg.Traefik.ConfigFile, out, 0644); err != nil {
		log.Error().Err(err).Msg("Unable to write traefik configuration")
	}

	return nil
}

func (a *App) Sync(cfg SyncConfig) error {
	if err := a.syncCerts(cfg); err != nil {
		return err
	}

	if err := a.writeTraefikConfig(cfg); err != nil {
		return err
	}

	return nil
}
