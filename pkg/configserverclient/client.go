package configserverclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config holds connection settings for the traefik config-server.
type Config struct {
	URL     string `env:"CONFIG_SERVER_URL" default:"" help:"Base URL of the traefik config-server (e.g. http://config-server:8000). Empty = disabled."`
	Node    string `env:"CONFIG_SERVER_NODE" default:"" help:"Node name to filter backends (e.g. lb-edge-par01). Empty = all backends."`
	Timeout int    `env:"CONFIG_SERVER_TIMEOUT" default:"5" help:"HTTP timeout in seconds for config-server requests."`
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

type backend struct {
	FQDN string `json:"fqdn"`
}

// New returns a ready-to-use Client. URL must be non-empty.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("config-server URL is required")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5
	}
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}, nil
}

// GetDomains returns all FQDNs from the config-server. If Node is set, only
// that node's assigned backends are returned; otherwise all backends are listed.
func (c *Client) GetDomains() ([]string, error) {
	var endpoint string
	if c.cfg.Node != "" {
		endpoint = fmt.Sprintf("%s/api/v1/nodes/%s/backends", c.cfg.URL, c.cfg.Node)
	} else {
		endpoint = fmt.Sprintf("%s/api/v1/backends", c.cfg.URL)
	}

	resp, err := c.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("config-server request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config-server returned HTTP %d", resp.StatusCode)
	}

	var backends []backend
	if err := json.NewDecoder(resp.Body).Decode(&backends); err != nil {
		return nil, fmt.Errorf("config-server decode error: %w", err)
	}

	domains := make([]string, 0, len(backends))
	for _, b := range backends {
		if b.FQDN != "" {
			domains = append(domains, b.FQDN)
		}
	}
	return domains, nil
}
