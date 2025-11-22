package app

import (
	"time"

	"github.com/rs/zerolog/log"
)

func (a *App) Renew(cfg RenewConfig) {
	// Initialize the required clients
	a.initBuckcert(cfg.Buckcert)

	if cfg.Traefik.Url != "" {
		a.initTraefikClient(cfg.Traefik)

		domains, err := a.traefikApi.GetDomains()
		if err != nil {
			log.Fatal().Err(err).Msg("unable to get domains from traefik")
		}

		cfg.Domains = append(cfg.Domains, domains...)
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

	a.renew(finalDomains)
}

func (a *App) renew(domains []string) {
	var failed []string
	renewed := 0

	index := a.closet.GetIndex()

	for _, domain := range domains {
		entry, exists := index.CertIndex[domain]

		if exists {
			// renew 2 months before expiration
			renewBefore := time.Now().AddDate(0, 2, 0)

			if entry.ExpirationDate.After(renewBefore) {
				log.Info().
					Str("domain", domain).
					Msg("Certificate already obtained and still valid")
				continue
			}
		}

		// Request new certificate
		cert, err := a.buckcert.RequestCert([]string{domain})
		if err != nil {
			log.Error().
				Err(err).
				Str("domain", domain).
				Msg("Failed to request certificate")
			failed = append(failed, domain)
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
			failed = append(failed, domain)
			continue
		}

		renewed++
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
