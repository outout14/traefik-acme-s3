package traefikclient

import "regexp"

const MatchDomainRegex = "Host\\([\"'`]?([^\"'`)]+)[\"'`]?\\)"

type TraefikRouter struct {
	// Only used to parse the rule
	Rule string `json:"rule"`
}

type TraefikRootConfig struct {
	Tls TraefikTLS `toml:"tls" yaml:"tls"`
}

type TraefikTLS struct {
	Certificates []TraefikCertificate `toml:"certificates" yaml:"certificates"`
}

type TraefikCertificate struct {
	CertFile string `toml:"certFile" yaml:"certFile"`
	KeyFile  string `toml:"keyFile" yaml:"keyFile"`
}

/* ParseRule parses the rule and returns the domain associated */
func (t *TraefikRouter) ParseRule() string {
	r := regexp.MustCompile(MatchDomainRegex).FindStringSubmatch(t.Rule)
	if len(r) > 1 {
		return r[1]
	}
	return ""
}
