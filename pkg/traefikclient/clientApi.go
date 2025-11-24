package traefikclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ApiClient struct {
	apiConfig  ApiConfig
	httpClient *http.Client
}

type ApiConfig struct {
	Url      string `env:"TRAEFIK_API_URL" help:"Traefik API URL to use to retrieve the domains."`
	Username string `env:"TRAEFIK_API_USERNAME" default:"" help:"Traefik API username to use to retrieve the domains."`
	Password string `env:"TRAEFIK_API_PASSWORD" default:"" help:"Traefik API password to use to retrieve the domains."`
	Timeout  int    `env:"TRAEFIK_API_TIMEOUT" default:"5" help:"Traefik API timeout in seconds."`
	Insecure bool   `env:"TRAEFIK_API_INSECURE" default:"false" help:"Allow insecure certificates when communicating with the Traefik API."`
}

// NewTraefikApiClient creates and returns a configured ApiClient based
// on the provided ApiConfig. It validates required fields, ensures the
// base URL ends with a slash, configures TLS options when Insecure is
// set, and returns a ready-to-use ApiClient or an error.
func NewTraefikApiClient(config ApiConfig) (*ApiClient, error) {
	cli := ApiClient{apiConfig: config}

	if cli.apiConfig.Url == "" {
		return nil, fmt.Errorf("traefik API URL is required")
	}
	if !strings.HasSuffix(cli.apiConfig.Url, "/") {
		config.Url += "/"
	}

	// Add the basic auth to the client
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cli.apiConfig.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	cli.httpClient = &http.Client{
		Timeout:   time.Duration(cli.apiConfig.Timeout) * time.Second,
		Transport: transport,
	}

	return &cli, nil
}

// makeRequest performs an HTTP GET against the Traefik API using the
// client's base URL and applies basic auth when configured. It returns
// the HTTP response or an error.
func (c *ApiClient) makeRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", c.apiConfig.Url, url), nil)
	if err != nil {
		return nil, err
	}
	if c.apiConfig.Username != "" && c.apiConfig.Password != "" {
		req.SetBasicAuth(c.apiConfig.Username, c.apiConfig.Password)
	}

	return c.httpClient.Do(req)
}
