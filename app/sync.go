package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

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

func isSafeDomainPathSegment(domain string) bool {
	if domain == "" || filepath.IsAbs(domain) {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}
	if strings.Contains(domain, "/") || strings.Contains(domain, "\\") {
		return false
	}
	for _, r := range domain {
		if r == 0 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

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
	if !isSafeDomainPathSegment(cert.Domain) {
		return fmt.Errorf("unsafe domain path segment: %q", cert.Domain)
	}

	dir := filepath.Join(basepath, cert.Domain)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, CERT_EXT), cert.Certificate, 0644); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, KEY_EXT), cert.PrivateKey, 0600); err != nil {
		return err
	}
	return nil
}

func (a *App) syncCerts(cfg SyncConfig) error {
	localCloset, err := certcloset.NewLocalCertCloset(a.config.Closet, cfg.Traefik.LocalStore)
	if err != nil {
		return err
	}
	remoteIdx := a.closet.GetIndex()
	localIdx := localCloset.GetIndex()
	icFailed := localCloset.CheckIntegrity()
	localChanged := false
	var failed []string

	for _, cert := range icFailed {
		log.Error().Str("domain", cert.Domain).Msg("Certificate file missing, it will be retrieved back from remote storage")
		localIdx.Remove(cert.Domain)
		localChanged = true
	}

	for domain := range localIdx.CertIndex {
		if _, ok := remoteIdx.CertIndex[domain]; ok {
			continue
		}
		log.Info().Str("domain", domain).Msg("Removing local certificate missing from remote index")
		if !isSafeDomainPathSegment(domain) {
			log.Error().Str("domain", domain).Msg("Unable to remove unsafe local certificate path")
			failed = append(failed, domain)
			continue
		}
		if err := os.RemoveAll(filepath.Join(cfg.Traefik.LocalStore, domain)); err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("Unable to remove stale local certificate")
			failed = append(failed, domain)
			continue
		}
		localIdx.Remove(domain)
		localChanged = true
	}

	diff := remoteIdx.GetDiff(localIdx)
	if len(diff) == 0 && !localChanged {
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
					failed = append(failed, crt.Domain)
				}
				if a.metrics != nil {
					a.metrics.removeDomain(crt.Domain)
				}
				if isSafeDomainPathSegment(crt.Domain) {
					if rmErr := os.RemoveAll(filepath.Join(cfg.Traefik.LocalStore, crt.Domain)); rmErr != nil {
						log.Error().Err(rmErr).Str("domain", crt.Domain).Msg("Unable to remove stale local certificate")
						failed = append(failed, crt.Domain)
					}
				} else {
					log.Error().Str("domain", crt.Domain).Msg("Unable to remove unsafe local certificate path")
					failed = append(failed, crt.Domain)
				}
				localIdx.Remove(crt.Domain)
				localChanged = true
			} else {
				log.Error().Err(err).Str("domain", crt.Domain).Msg("Unable to retrieve certificate")
				failed = append(failed, crt.Domain)
			}
			continue
		}

		if err = a.writeCertificate(cfg.Traefik.LocalStore, cert); err != nil {
			log.Error().Err(err).Str("domain", cert.Domain).Msg("Unable to store certificate")
			failed = append(failed, cert.Domain)
			continue
		}
		if entry, ok := remoteIdx.CertIndex[crt.Domain]; ok {
			localIdx.Add(entry)
			localChanged = true
		}
		log.Info().Str("domain", crt.Domain).Msg("Certificate synced")
	}

	if localChanged {
		if err := localCloset.SaveIndex(); err != nil {
			return err
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		return fmt.Errorf("sync failed for %d certificate(s): %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
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
		if !isSafeDomainPathSegment(domain) {
			log.Error().Str("domain", domain).Msg("HAProxy: unsafe domain path segment, skipping")
			continue
		}
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

		bundle := make([]byte, 0, len(certData)+len(keyData)+1)
		bundle = append(bundle, certData...)
		if len(certData) > 0 && certData[len(certData)-1] != '\n' {
			bundle = append(bundle, '\n')
		}
		bundle = append(bundle, keyData...)
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
	if cfg.Traefik.CertificateDir == "" {
		return fmt.Errorf("traefik certificate dir is required when traefik output file is set")
	}

	tcfg := traefikclient.TraefikRootConfig{
		Tls: traefikclient.TraefikTLS{
			Certificates: make([]traefikclient.TraefikCertificate, 0),
		},
	}

	for domain := range a.closet.GetIndex().CertIndex {
		if !isSafeDomainPathSegment(domain) {
			log.Error().Str("domain", domain).Msg("Traefik: unsafe domain path segment, skipping")
			continue
		}
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
		stopLockRefresh := a.startLockRefresh()
		defer a.state.ReleaseLock()
		defer stopLockRefresh()
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
