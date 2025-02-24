package traefikclient

import (
	"encoding/json"
	"fmt"
)

func (c *ApiClient) GetDomains() ([]string, error) {
	var domains []string

	resp, err := c.makeRequest("api/http/routers")
	if err != nil {
		return domains, fmt.Errorf("unable to make request to the Traefik API: %w", err)
	}
	defer resp.Body.Close()

	var routers []TraefikRouter
	if err := json.NewDecoder(resp.Body).Decode(&routers); err != nil {
		return domains, fmt.Errorf("unable to decode response from the Traefik API: %w", err)
	}

	for _, router := range routers {
		if router.ParseRule() != "" {
			domains = append(domains, router.ParseRule())
		}
	}

	return domains, nil
}
