package dnsupdate

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// findAuthNS walks up domain labels querying SOA to locate the zone apex
// and its primary nameserver (MNAME from the SOA record).
//
// resolverAddr is "host:port"; empty means read servers from /etc/resolv.conf
// with a fallback to 8.8.8.8:53.
func findAuthNS(domain, resolverAddr string) (nameserver, zoneApex string, err error) {
	servers, err := resolvers(resolverAddr)
	if err != nil {
		return "", "", err
	}

	c := new(dns.Client)
	d := dns.Fqdn(strings.TrimSuffix(domain, "."))

	for d != "." && d != "" {
		m := new(dns.Msg)
		m.SetQuestion(d, dns.TypeSOA)
		m.RecursionDesired = true

		resp, queryErr := exchangeAny(c, m, servers)
		if queryErr != nil {
			return "", "", fmt.Errorf("SOA query for %s: %w", d, queryErr)
		}

		// SOA may appear in Answer (zone apex) or Ns (authority) section.
		for _, rr := range append(resp.Answer, resp.Ns...) {
			if soa, ok := rr.(*dns.SOA); ok {
				return dns.Fqdn(soa.Ns), soa.Hdr.Name, nil
			}
		}

		// Strip leftmost label and retry.
		bare := strings.TrimSuffix(d, ".")
		dot := strings.IndexByte(bare, '.')
		if dot < 0 {
			break
		}
		d = bare[dot+1:] + "."
	}

	return "", "", fmt.Errorf("no SOA found for %s or any parent zone", domain)
}

func resolvers(addr string) ([]string, error) {
	if addr != "" {
		return []string{addr}, nil
	}
	cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return []string{"8.8.8.8:53"}, nil
	}
	out := make([]string, len(cc.Servers))
	for i, s := range cc.Servers {
		out[i] = net.JoinHostPort(s, cc.Port)
	}
	return out, nil
}

func exchangeAny(c *dns.Client, m *dns.Msg, servers []string) (*dns.Msg, error) {
	var lastErr error
	for _, srv := range servers {
		resp, _, err := c.Exchange(m, srv)
		if err == nil && resp != nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
