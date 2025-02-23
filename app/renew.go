package app

import (
	"crypto"
	"time"

	"github.com/go-acme/lego/v4/registration"
	"github.com/rs/zerolog/log"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (a *App) Renew() {
	if len(a.config.Domains) == 0 {
		log.Warn().Msg("No domains. Exiting")
		return
	}

	var fails []string

	index := a.closet.GetIndex()

	for _, domain := range a.config.Domains {
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

		/* err := a.closet.StoreCertificate(certificate.Resource{
			Domain:      domain,
			PrivateKey:  []byte("private key"),
			Certificate: []byte("certificate"),
		}) */
		if err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("Failed to store certificate")
			fails = append(fails, domain)
			continue
		}

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
