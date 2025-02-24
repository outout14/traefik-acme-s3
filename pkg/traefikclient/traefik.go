package traefikclient

import "regexp"

const MatchDomainRegex = "Host\\([\"'`]?([^\"'`)]+)[\"'`]?\\)"

type TraefikRouter struct {
	// Only used to parse the rule
	Rule string `json:"rule"`
}

/* ParseRule parses the rule and returns the domain associated */
func (t *TraefikRouter) ParseRule() string {
	r := regexp.MustCompile(MatchDomainRegex).FindStringSubmatch(t.Rule)
	if len(r) > 1 {
		return r[1]
	}
	return ""
}
