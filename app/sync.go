package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

// atomicWrite writes content to path via a temp file + rename so readers (e.g. Traefik) never
// see a partially-written file.
func atomicWrite(path string, content []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *App) writeCertificate(basepath string, cert *certcloset.Certificate) error {
	dir := filepath.Join(basepath, cert.Domain)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for path, content := range map[string][]byte{
		filepath.Join(dir, CERT_EXT): cert.Certificate,
		filepath.Join(dir, KEY_EXT):  cert.PrivateKey,
	} {
		if err := atomicWrite(path, content, 0644); err != nil {
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
			if certcloset.IsErrNotFound(err) {
				log.Warn().Str("domain", crt.Domain).Msg("Certificate in index but missing in S3 — removing stale index entry")
				a.closet.RemoveFromIndex(crt.Domain)
				if saveErr := a.closet.SaveIndex(); saveErr != nil {
					log.Error().Err(saveErr).Str("domain", crt.Domain).Msg("Failed to save index after removing stale entry")
				}
				if a.metrics != nil {
					a.metrics.removeDomain(crt.Domain)
				}
			} else {
				log.Error().Err(err).Str("domain", crt.Domain).Msg("Unable to retrieve certificate")
			}
			continue
		}

		if err = a.writeCertificate(cfg.Traefik.LocalStore, cert); err != nil {
			log.Error().Err(err).Str("domain", cert.Domain).Msg("Unable to store certificate")
		}
		log.Info().Str("domain", crt.Domain).Msg("Certificate synced")
	}

	localCloset.SetIndex(a.closet.GetIndex())
	return localCloset.SaveIndex()
}

func (a *App) writeHAProxyConfig(cfg SyncConfig) error {
	if cfg.HAProxy.CertDir == "" {
		return nil
	}

	if err := os.MkdirAll(cfg.HAProxy.CertDir, 0755); err != nil {
		return fmt.Errorf("create haproxy cert dir: %w", err)
	}

	refDir := cfg.HAProxy.CertDirRef
	if refDir == "" {
		refDir = cfg.HAProxy.CertDir
	}

	var crtListLines []string

	for domain := range a.closet.GetIndex().CertIndex {
		certData, err := os.ReadFile(filepath.Join(cfg.Traefik.LocalStore, domain, CERT_EXT))
		if err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("HAProxy: cannot read cert file")
			continue
		}
		keyData, err := os.ReadFile(filepath.Join(cfg.Traefik.LocalStore, domain, KEY_EXT))
		if err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("HAProxy: cannot read key file")
			continue
		}

		bundle := append(certData, keyData...)
		bundlePath := filepath.Join(cfg.HAProxy.CertDir, domain+".pem")
		if err := atomicWrite(bundlePath, bundle, 0600); err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("HAProxy: cannot write bundle")
			continue
		}

		if cfg.HAProxy.CrtListFile != "" {
			crtListLines = append(crtListLines, filepath.Join(refDir, domain+".pem")+" "+domain)
		}
	}

	if cfg.HAProxy.CrtListFile != "" {
		sort.Strings(crtListLines)
		content := strings.Join(crtListLines, "\n") + "\n"
		if err := atomicWrite(cfg.HAProxy.CrtListFile, []byte(content), 0644); err != nil {
			return fmt.Errorf("write haproxy crt-list: %w", err)
		}
	}

	return nil
}

func (a *App) writeTraefikConfig(cfg SyncConfig) error {
	if cfg.Traefik.ConfigFile == "" {
		return nil
	}

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
	switch cfg.Traefik.Format {
	case "toml":
		out, err = toml.Marshal(tcfg)
	case "yaml":
		out, err = yaml.Marshal(tcfg)
	default:
		return fmt.Errorf("unsupported traefik config format: %s", cfg.Traefik.Format)
	}
	if err != nil {
		return fmt.Errorf("marshal traefik config: %w", err)
	}

	if err := atomicWrite(cfg.Traefik.ConfigFile, out, 0644); err != nil {
		return fmt.Errorf("write traefik config: %w", err)
	}

	return nil
}

func (a *App) Sync(cfg SyncConfig) error {
	if a.state != nil {
		if err := a.state.AcquireLock(); err != nil {
			log.Error().Err(err).Msg("Could not acquire distributed lock — skipping sync run")
			return nil
		}
		defer a.state.ReleaseLock()
	}

	if err := a.syncCerts(cfg); err != nil {
		if a.metrics != nil {
			a.metrics.syncTotal.WithLabelValues("fail").Inc()
		}
		return err
	}

	if err := a.writeTraefikConfig(cfg); err != nil {
		if a.metrics != nil {
			a.metrics.syncTotal.WithLabelValues("fail").Inc()
		}
		return err
	}

	if err := a.writeHAProxyConfig(cfg); err != nil {
		if a.metrics != nil {
			a.metrics.syncTotal.WithLabelValues("fail").Inc()
		}
		return err
	}

	now := time.Now()
	a.mu.Lock()
	a.lastSync = now
	a.mu.Unlock()

	if a.metrics != nil {
		a.metrics.syncTotal.WithLabelValues("ok").Inc()
		a.metrics.lastSyncTs.Set(float64(now.Unix()))
	}

	return nil
}
