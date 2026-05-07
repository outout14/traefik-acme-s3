package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/outout14/traefik-acme-s3/pkg/dnsupdate"
	"github.com/rs/zerolog/log"
)

const (
	getDomainsMaxAttempts    = 3
	getDomainsInitialBackoff = 5 * time.Second
)

func (a *App) Renew(cfg RenewConfig) {
	a.initBuckcert(cfg.Buckcert)
	a.initDNSUpdater(cfg.DNSUpdate, cfg.Buckcert.CaURL)

	if cfg.Traefik.Url != "" {
		a.initTraefikClient(cfg.Traefik)

		domains, err := a.getDomainsWithRetry(getDomainsMaxAttempts, getDomainsInitialBackoff)
		if err != nil {
			log.Error().Err(err).Msg("Traefik API GetDomains failed after retries — using only configured DOMAINS for this run")
		} else {
			cfg.Domains = append(cfg.Domains, domains...)
		}
	} else {
		log.Warn().Msg("No traefik API URL provided. Skipping traefik client initialization")
	}

	ignored := make(map[string]struct{}, len(cfg.IgnoredDomains))
	for _, domain := range cfg.IgnoredDomains {
		ignored[domain] = struct{}{}
	}

	unique := make(map[string]struct{})
	for _, domain := range cfg.Domains {
		if _, skip := ignored[domain]; !skip {
			unique[domain] = struct{}{}
		}
	}

	finalDomains := make([]string, 0, len(unique))
	for domain := range unique {
		finalDomains = append(finalDomains, domain)
	}

	if len(finalDomains) == 0 {
		log.Warn().Msg("No domains provided after filtering — exiting")
		return
	}

	a.renew(cfg, finalDomains)

	now := time.Now()
	a.mu.Lock()
	a.lastRenew = now
	a.mu.Unlock()

	if a.metrics != nil {
		a.metrics.lastRenewTs.Set(float64(now.Unix()))
		for domain, entry := range a.closet.GetIndex().CertIndex {
			a.metrics.certExpiry.WithLabelValues(domain).Set(float64(entry.ExpirationDate.Unix()))
		}
	}
}

func (a *App) renew(cfg RenewConfig, domains []string) {
	if a.state != nil {
		if err := a.state.AcquireLock(); err != nil {
			log.Error().Err(err).Msg("Could not acquire distributed lock — skipping renew run")
			return
		}
		defer a.state.ReleaseLock()
	}

	state, err := a.loadFailureState()
	if err != nil {
		log.Warn().Err(err).Msg("Could not load failure state — continuing without backoff")
		state = &certcloset.FailureState{LastFailure: make(map[string]string)}
	}

	index := a.closet.GetIndex()
	renewed := 0
	var failed []string
	requestDelay := time.Duration(cfg.RequestDelaySeconds) * time.Second
	if requestDelay <= 0 {
		requestDelay = 3 * time.Second
	}
	needDelay := false

	for _, domain := range domains {
		baseDomain := strings.TrimPrefix(domain, "*.")
		isWildcard := domain != baseDomain

		if a.isInBackoff(state, domain, cfg.FailureBackoffMinutes) {
			log.Debug().Str("domain", domain).Int("backoff_min", cfg.FailureBackoffMinutes).
				Msg("Skipping domain in failure backoff")
			continue
		}

		// Advance in-progress rollover before attempting normal renewal.
		if a.state != nil && !isWildcard && a.dnsUpdate != nil {
			rollover, exists, err := a.state.LoadRolloverState(domain)
			if err != nil {
				log.Error().Err(err).Str("domain", domain).Msg("Failed to load rollover state")
				a.recordFailure(state, domain)
				_ = a.saveFailureState(state)
				if a.metrics != nil {
					a.metrics.renewTotal.WithLabelValues(domain, "fail").Inc()
				}
				failed = append(failed, domain)
				continue
			}
			if exists {
				if err := a.advanceRollover(domain, baseDomain, rollover, cfg, &renewed); err != nil {
					log.Error().Err(err).Str("domain", domain).Msg("Failed to advance rollover")
					a.recordFailure(state, domain)
					_ = a.saveFailureState(state)
					if a.metrics != nil {
						a.metrics.renewTotal.WithLabelValues(domain, "fail").Inc()
					}
					failed = append(failed, domain)
				}
				continue
			}
		}

		// Check whether renewal is needed.
		entry, entryExists := index.CertIndex[domain]
		renewBefore := time.Now().AddDate(0, 2, 0)

		if entryExists && entry.ExpirationDate.After(renewBefore) {
			existsInS3, err := a.closet.CertificateExists(domain)
			if err != nil {
				log.Warn().Err(err).Str("domain", domain).Msg("Could not verify certificate in S3, skipping")
				continue
			}
			if existsInS3 {
				log.Info().Str("domain", domain).Msg("Certificate already obtained and still valid")
				a.clearFailure(state, domain)
				_ = a.saveFailureState(state)
				continue
			}
			log.Warn().Str("domain", domain).Msg("Certificate in index but missing in S3 — removing stale entry")
			a.closet.RemoveFromIndex(domain)
			_ = a.closet.SaveIndex()
			if a.metrics != nil {
				a.metrics.removeDomain(domain)
			}
		}

		if needDelay {
			time.Sleep(requestDelay)
		}

		// Decide whether to start a TLSA rollover or use the simple renewal path.
		useRollover := a.state != nil &&
			a.dnsUpdate != nil &&
			cfg.DNSUpdate.RolloverEnabled &&
			!isWildcard &&
			a.dnsUpdate.Enabled(baseDomain)

		if useRollover {
			if err := a.startRollover(domain, baseDomain, cfg); err != nil {
				log.Error().Err(err).Str("domain", domain).Msg("Failed to start TLSA rollover")
				a.recordFailure(state, domain)
				_ = a.saveFailureState(state)
				if a.metrics != nil {
					a.metrics.renewTotal.WithLabelValues(domain, "fail").Inc()
				}
				failed = append(failed, domain)
			}
		} else {
			cert, err := a.buckcert.RequestCert([]string{domain})
			if err != nil {
				log.Error().Err(err).Str("domain", domain).Str("event", "cert_request_failed").
					Msg("Failed to request certificate")
				a.recordFailure(state, domain)
				_ = a.saveFailureState(state)
				if a.metrics != nil {
					a.metrics.renewTotal.WithLabelValues(domain, "fail").Inc()
				}
				failed = append(failed, domain)
				needDelay = true
				continue
			}
			log.Info().Str("domain", domain).Str("event", "cert_obtained").Msg("Certificate obtained")

			if err := a.closet.StoreCertificate(*cert); err != nil {
				log.Error().Err(err).Str("domain", domain).Str("event", "cert_store_failed").
					Msg("Failed to store certificate")
				a.recordFailure(state, domain)
				_ = a.saveFailureState(state)
				if a.metrics != nil {
					a.metrics.renewTotal.WithLabelValues(domain, "fail").Inc()
				}
				failed = append(failed, domain)
				needDelay = true
				continue
			}

			if a.dnsUpdate != nil {
				if err := a.dnsUpdate.UpdateDNS(domain, cert.Certificate); err != nil {
					log.Warn().Err(err).Str("domain", domain).Msg("DNS UPDATE failed — certificate stored")
				}
			}

			a.clearFailure(state, domain)
			_ = a.saveFailureState(state)
			if a.metrics != nil {
				a.metrics.renewTotal.WithLabelValues(domain, "ok").Inc()
			}
			renewed++
		}
		needDelay = true
	}

	if renewed == 0 {
		log.Info().Msg("No certificates required renewal")
		return
	}

	if err := a.closet.SaveIndex(); err != nil {
		log.Error().Err(err).Msg("Failed to save certificate index")
	}

	if len(failed) == 0 {
		log.Info().Msg("All certificates obtained and stored successfully")
		return
	}
	log.Error().Strs("domains", failed).Msg("Failed to request certificates for these domains")
}

// startRollover kicks off Phase 1: generate a new key, pre-publish its TLSA alongside the
// existing one, and persist rollover state + pending key to S3.
func (a *App) startRollover(domain, baseDomain string, cfg RenewConfig) error {
	oldTLSAHex := ""
	if existing, err := a.closet.RetrieveCertificate(domain); err == nil && len(existing.Certificate) > 0 {
		if hex, err2 := dnsupdate.TLSAHexFromCertPEM(existing.Certificate); err2 == nil {
			oldTLSAHex = hex
		}
	}

	keyPEM, newTLSAHex, err := dnsupdate.GenerateKeyAndTLSA()
	if err != nil {
		return fmt.Errorf("generate key and TLSA: %w", err)
	}

	if err := a.dnsUpdate.AddTLSA(baseDomain, newTLSAHex); err != nil {
		return fmt.Errorf("pre-publish TLSA: %w", err)
	}

	if err := a.state.StorePendingKey(domain, keyPEM); err != nil {
		return fmt.Errorf("store pending key: %w", err)
	}

	ttlSec := cfg.DNSUpdate.TLSATTLSeconds
	if ttlSec <= 0 {
		ttlSec = 3600
	}
	lagSec := cfg.DNSUpdate.SyncLagSeconds
	if lagSec <= 0 {
		lagSec = 300
	}

	rs := &certcloset.RolloverState{
		Phase:          certcloset.RolloverPhasePrePublishing,
		OldTLSAHex:     oldTLSAHex,
		NewTLSAHex:     newTLSAHex,
		PhaseStartedAt: time.Now(),
		TLSATTLSeconds: ttlSec,
		SyncLagSeconds: lagSec,
	}
	if err := a.state.StoreRolloverState(domain, rs); err != nil {
		return fmt.Errorf("store rollover state: %w", err)
	}

	log.Info().
		Str("domain", domain).
		Str("new_tlsa", newTLSAHex).
		Str("old_tlsa", oldTLSAHex).
		Int("ttl_seconds", ttlSec).
		Msg("TLSA pre-published, waiting for TTL to expire")
	return nil
}

// advanceRollover moves a domain's rollover state forward by one phase if the required wait
// has elapsed. renewed is incremented when a certificate is successfully stored.
func (a *App) advanceRollover(domain, baseDomain string, rollover *certcloset.RolloverState, cfg RenewConfig, renewed *int) error {
	switch rollover.Phase {
	case certcloset.RolloverPhasePrePublishing:
		// Detect missing pending key — partial start (AddTLSA succeeded but StorePendingKey failed).
		// Reset so the next run starts fresh.
		if _, err := a.state.LoadPendingKey(domain); err != nil {
			log.Error().Err(err).Str("domain", domain).
				Msg("Rollover inconsistent: pending key missing — resetting rollover state")
			_ = a.state.DeleteRolloverState(domain)
			return nil
		}

		wait := time.Duration(rollover.TLSATTLSeconds) * time.Second
		elapsed := time.Since(rollover.PhaseStartedAt)
		if elapsed < wait {
			log.Info().Str("domain", domain).
				Str("elapsed", elapsed.Round(time.Second).String()).
				Str("wait", wait.String()).
				Msg("TLSA pre-publish: waiting for TTL")
			return nil
		}

		keyPEM, err := a.state.LoadPendingKey(domain)
		if err != nil {
			return fmt.Errorf("load pending key: %w", err)
		}

		cert, err := a.buckcert.RequestCertWithKey([]string{domain}, keyPEM)
		if err != nil {
			return fmt.Errorf("request cert with key: %w", err)
		}

		if err := a.closet.StoreCertificate(*cert); err != nil {
			return fmt.Errorf("store certificate: %w", err)
		}
		*renewed++

		rs := &certcloset.RolloverState{
			Phase:          certcloset.RolloverPhaseCertSwitched,
			OldTLSAHex:     rollover.OldTLSAHex,
			NewTLSAHex:     rollover.NewTLSAHex,
			PhaseStartedAt: time.Now(),
			SyncLagSeconds: rollover.SyncLagSeconds,
		}
		if err := a.state.StoreRolloverState(domain, rs); err != nil {
			return fmt.Errorf("update rollover state: %w", err)
		}

		if err := a.dnsUpdate.UpdateCAA(baseDomain); err != nil {
			log.Warn().Err(err).Str("domain", domain).Msg("CAA update failed — non-fatal")
		}

		log.Info().Str("domain", domain).Int("sync_lag_seconds", rollover.SyncLagSeconds).
			Msg("Certificate switched, waiting sync lag before removing old TLSA")

	case certcloset.RolloverPhaseCertSwitched:
		wait := time.Duration(rollover.SyncLagSeconds) * time.Second
		elapsed := time.Since(rollover.PhaseStartedAt)
		if elapsed < wait {
			log.Info().Str("domain", domain).
				Str("elapsed", elapsed.Round(time.Second).String()).
				Str("wait", wait.String()).
				Msg("Cert switched: waiting sync lag")
			return nil
		}

		if rollover.OldTLSAHex != "" {
			if err := retryRemoveTLSA(a.dnsUpdate, baseDomain, rollover.OldTLSAHex); err != nil {
				// Force cleanup after 10× sync lag to avoid a permanently stuck rollover.
				forceAfter := time.Duration(rollover.SyncLagSeconds*10) * time.Second
				if time.Since(rollover.PhaseStartedAt) < forceAfter {
					log.Error().Err(err).Str("domain", domain).
						Msg("RemoveTLSA failed after retries — will retry next run")
					return err
				}
				log.Error().Err(err).Str("domain", domain).
					Msg("RemoveTLSA failed repeatedly and rollover is ancient — forcing cleanup")
			}
		}
		_ = a.state.DeletePendingKey(domain)
		if err := a.state.DeleteRolloverState(domain); err != nil {
			return fmt.Errorf("delete rollover state: %w", err)
		}

		log.Info().Str("domain", domain).Msg("TLSA rollover complete")
	}

	return nil
}

// retryRemoveTLSA retries RemoveTLSA up to 3 times with linear backoff.
func retryRemoveTLSA(u dnsUpdater, domain, tlsaHex string) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		if lastErr = u.RemoveTLSA(domain, tlsaHex); lastErr == nil {
			return nil
		}
		log.Warn().Err(lastErr).Str("domain", domain).Int("attempt", attempt+1).
			Msg("RemoveTLSA failed, retrying")
	}
	return lastErr
}
