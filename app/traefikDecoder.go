package app

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/rs/zerolog/log"
)

type TraefikRouter struct {
	Rule string `json:"rule"`
}

const MatchDomainRegex = "Host\\([\"'`]?([^\"'`)]+)[\"'`]?\\)"

func (a *App) loadDomains() {
	// Request api
	api := &http.Client{}
	req, err := http.NewRequest("GET", a.config.Traefik.ApiURL+"/api/http/routers", nil)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to create a request to the Traefik API")
	}
	if a.config.Traefik.ApiUsername != "" && a.config.Traefik.ApiPassword != "" {
		log.Info().Str("api_url", a.config.Traefik.ApiURL).Msg("Using basic auth to access Traefik API")
		req.SetBasicAuth(a.config.Traefik.ApiUsername, a.config.Traefik.ApiPassword)
	}

	resp, err := api.Do(req)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to get routers from the Traefik API")
	}

	defer resp.Body.Close()

	// -- end request api

	// Parse the response
	var routers []TraefikRouter

	if err := json.NewDecoder(resp.Body).Decode(&routers); err != nil {
		log.Fatal().Err(err).Msg("Unable to decode response from the Traefik API")
	}
	// -- end parse response

	for _, router := range routers {
		if router.ParseRule() != "" {
			a.config.Domains = append(a.config.Domains, router.ParseRule())
		}
	}
}

/* ParseRule parses the rule and returns the domain associated */
func (t *TraefikRouter) ParseRule() string {
	r := regexp.MustCompile(MatchDomainRegex).FindStringSubmatch(t.Rule)
	if len(r) > 1 {
		return r[1]
	}
	return ""
}
