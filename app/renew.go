package app

import (
	"time"

	"github.com/rs/zerolog/log"
)

const (
	getDomainsMaxAttempts = 3
	getDomainsInitialBackoff = 5 * time.Second
)

func (a *App) Renew(cfg RenewConfig) {
	// Initialize the required clients
	a.initBuckcert(cfg.Buckcert)

	if cfg.Traefik.Url != "" {
		a.initTraefikClient(cfg.Traefik)

		domains, err := a.getDomainsWithRetry(getDomainsMaxAttempts, getDomainsInitialBackoff)
		if err != nil {
			log.Error().Err(err).Msg("Traefik API GetDomains failed after retries — using only configured DOMAINS for this run")
			// Continue with cfg.Domains only; next Ofelia run (5 min) will retry
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

	// Produce final list
	finalDomains := make([]string, 0, len(unique))
	for domain := range unique {
		finalDomains = append(finalDomains, domain)
	}

	if len(finalDomains) == 0 {
		log.Warn().Msg("No domains provided after filtering — exiting")
		return
	}

	a.renew(cfg, finalDomains)
}

func (a *App) renew(cfg RenewConfig, domains []string) {
	var failed []string
	renewed := 0
	requestDelay := time.Duration(cfg.RequestDelaySeconds) * time.Second
	if requestDelay <= 0 {
		requestDelay = 3 * time.Second
	}

	state, err := a.loadFailureState(cfg.StateDir)
	if err != nil {
		log.Warn().Err(err).Msg("Could not load failure state — continuing without backoff")
		state = &failureState{LastFailure: make(map[string]string)}
	}

	index := a.closet.GetIndex()
	needDelay := false

	for _, domain := range domains {
		if a.isInBackoff(state, domain, cfg.FailureBackoffMinutes) {
			log.Debug().Str("domain", domain).
				Int("backoff_minutes", cfg.FailureBackoffMinutes).
				Msg("Skipping domain in failure backoff period")
			continue
		}

		entry, exists := index.CertIndex[domain]

		if exists {
			// renew 2 months before expiration
			renewBefore := time.Now().AddDate(0, 2, 0)

			if entry.ExpirationDate.After(renewBefore) {
				// Index says we have a valid cert — verify it actually exists in S3
				existsInS3, err := a.closet.CertificateExists(domain)
				if err != nil {
					log.Warn().Err(err).Str("domain", domain).Msg("Could not verify certificate in S3, skipping renewal this run")
					continue
				}
				if !existsInS3 {
					log.Warn().Str("domain", domain).Msg("Certificate in index but missing in S3 — removing stale entry and requesting renewal")
					index.Remove(domain)
					_ = a.closet.SaveIndex()
					// fall through to request cert
				} else {
					log.Info().
						Str("domain", domain).
						Msg("Certificate already obtained and still valid")
					a.clearFailure(state, domain)
					_ = a.saveFailureState(cfg.StateDir, state)
					continue
				}
			}
		}

		if needDelay {
			time.Sleep(requestDelay)
		}

		// Request new certificate
		cert, err := a.buckcert.RequestCert([]string{domain})
		if err != nil {
			log.Error().
				Err(err).
				Str("domain", domain).
				Msg("Failed to request certificate")
			a.recordFailure(state, domain)
			_ = a.saveFailureState(cfg.StateDir, state)
			failed = append(failed, domain)
			needDelay = true
			continue
		}

		log.Info().
			Str("domain", domain).
			Msg("Certificate successfully obtained")

		// Store certificate
		if err := a.closet.StoreCertificate(*cert); err != nil {
			log.Error().
				Err(err).
				Str("domain", domain).
				Msg("Failed to store certificate")
			a.recordFailure(state, domain)
			_ = a.saveFailureState(cfg.StateDir, state)
			failed = append(failed, domain)
			needDelay = true
			continue
		}

		a.clearFailure(state, domain)
		_ = a.saveFailureState(cfg.StateDir, state)
		renewed++
		needDelay = true
	}

	if renewed == 0 {
		log.Info().Msg("No certificates required renewal")
		return
	}

	// Persist index
	if err := a.closet.SaveIndex(); err != nil {
		log.Error().Err(err).Msg("Failed to save certificate index")
	}

	if len(failed) == 0 {
		log.Info().Msg("All certificates obtained and stored successfully")
		return
	}

	log.Error().
		Strs("domains", failed).
		Msg("Failed to request certificates for these domains")
}
