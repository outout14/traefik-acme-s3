package traefikclient

import "regexp"

const MatchDomainRegex = "Host\\([\"'`]?([^\"'`)]+)[\"'`]?\\)"
const MatchHostCallRegex = `Host\(([^)]*)\)`
const MatchQuotedDomainRegex = "[\"'`]([^\"'`]+)[\"'`]"

var (
	matchDomainRegex       = regexp.MustCompile(MatchDomainRegex)
	matchHostCallRegex     = regexp.MustCompile(MatchHostCallRegex)
	matchQuotedDomainRegex = regexp.MustCompile(MatchQuotedDomainRegex)
)

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
	domains := t.ParseDomains()
	if len(domains) > 0 {
		return domains[0]
	}
	r := matchDomainRegex.FindStringSubmatch(t.Rule)
	if len(r) > 1 {
		return r[1]
	}
	return ""
}

// ParseDomains parses the rule and returns every host found in Host(...) clauses.
func (t *TraefikRouter) ParseDomains() []string {
	hostCalls := matchHostCallRegex.FindAllStringSubmatch(t.Rule, -1)
	if len(hostCalls) == 0 {
		return nil
	}
	domains := make([]string, 0)
	for _, call := range hostCalls {
		if len(call) < 2 {
			continue
		}
		matches := matchQuotedDomainRegex.FindAllStringSubmatch(call[1], -1)
		for _, m := range matches {
			if len(m) > 1 {
				domains = append(domains, m[1])
			}
		}
	}
	if len(domains) == 0 {
		return nil
	}
	return domains
}

func parseRuleDomains(rule string) []string {
	r := TraefikRouter{Rule: rule}
	if domains := r.ParseDomains(); len(domains) > 0 {
		return domains
	}
	if domain := r.ParseRule(); domain != "" {
		return []string{domain}
	}
	return nil
}
