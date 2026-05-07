package dnsupdate

import (
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

var knownIssuers = []struct {
	suffix string
	issuer string
}{
	{"letsencrypt.org", "letsencrypt.org"},
	{"buypass.com", "buypass.com"},
	{"zerossl.com", "zerossl.com"},
	{"sectigo.com", "sectigo.com"},
}

// deriveIssuer extracts a CAA-compatible issuer string from an ACME CA URL.
// Falls back to the eTLD+1 of the URL host.
func deriveIssuer(caURL string) string {
	u, err := url.Parse(caURL)
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Hostname()
	for _, k := range knownIssuers {
		if host == k.suffix || strings.HasSuffix(host, "."+k.suffix) {
			return k.issuer
		}
	}
	// Fallback: last two labels of host
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// buildCAARecords returns CAA records for the zone apex.
// Always includes issue + issuewild. Appends iodef when non-empty.
// When accountURI is non-empty, embeds it as RFC 8657 accounturi parameter
// to restrict issuance to that specific ACME account.
func buildCAARecords(zone, issuer, accountURI, iodef string, ttl uint32) []dns.RR {
	apex := dns.Fqdn(zone)
	newHdr := func() dns.RR_Header {
		return dns.RR_Header{Name: apex, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: ttl}
	}
	issuerValue := issuerWithAccount(issuer, accountURI)
	records := []dns.RR{
		&dns.CAA{Hdr: newHdr(), Flag: 0, Tag: "issue", Value: issuerValue},
		&dns.CAA{Hdr: newHdr(), Flag: 0, Tag: "issuewild", Value: issuerValue},
	}
	if iodef != "" {
		records = append(records, &dns.CAA{Hdr: newHdr(), Flag: 0, Tag: "iodef", Value: iodef})
	}
	return records
}

// issuerWithAccount formats the CAA issue/issuewild value, optionally appending
// the RFC 8657 accounturi parameter.
func issuerWithAccount(issuer, accountURI string) string {
	if accountURI == "" {
		return issuer
	}
	return issuer + "; accounturi=" + accountURI
}
