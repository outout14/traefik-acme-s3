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

	if len(cfg.Domains) == 0 {
		log.Warn().Msg("No domains. Exiting")
		return
	}

	a.renew(cfg)
}

func (a *App) renew(cfg RenewConfig) {
	var fails []string

	done := 0

	index := a.closet.GetIndex()

	for _, domain := range cfg.Domains {
		if _, ok := index.CertIndex[domain]; ok {
			log.Info().Str("domain", domain).Msg("Certificate already obtained")
			if index.CertIndex[domain].ExpirationDate.After(time.Now().AddDate(0, -2, 0)) { // TODO : Customize the expiration date check
				log.Info().Str("domain", domain).Msg("Certificate still valid")
				continue
			}
		}

		cert, err := a.buckcert.RequestCert([]string{domain})
		if err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("Failed to request certificate")
			fails = append(fails, domain)
			continue
		}

		log.Info().Str("domain", domain).Msg("Certificate obtained")

		err = a.closet.StoreCertificate(*cert)

		if err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("Failed to store certificate")
			fails = append(fails, domain)
			continue
		}
		done++
	}

	if done == 0 {
		log.Info().Msg("No certificates to renew")
		return
	}

	err := a.closet.SaveIndex()
	if err != nil {
		log.Error().Err(err).Msg("Failed to save index")
	}

	if len(fails) == 0 {
		log.Info().Msg("All certificates obtained and stored")
		return
	}

	log.Error().Strs("domains", fails).Msg("Failed to request certificates for theses domains")
}
