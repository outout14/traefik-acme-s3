package dnsupdate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// Updater pushes TLSA and CAA records via DNS UPDATE (RFC 2136) with TSIG signing.
type Updater struct {
	cfg        Config
	keys       keyMap
	caURL      string
	accountURI string // RFC 8657 accounturi embedded in CAA records; empty = omit
}

// New builds an Updater. caURL is the ACME CA directory URL used to derive CAA issuer.
// accountURI is the ACME account URL (e.g. from registration); empty = no accounturi in CAA.
func New(cfg Config, caURL, accountURI string) (*Updater, error) {
	var keys keyMap
	if cfg.KeysFile != "" {
		var err error
		keys, err = loadKeysFile(cfg.KeysFile)
		if err != nil {
			return nil, fmt.Errorf("load DNS update keys: %w", err)
		}
	}
	return &Updater{cfg: cfg, keys: keys, caURL: caURL, accountURI: accountURI}, nil
}

// Enabled reports whether a TSIG key is configured for domain.
// Returns false when DNS UPDATE would be silently skipped.
func (u *Updater) Enabled(domain string) bool {
	_, ok := u.keys.keyFor(domain)
	return ok
}

// UpdateDNS pushes TLSA (skipped for wildcards) and CAA records for domain.
// Returns nil without error when no TSIG key is configured for the domain.
func (u *Updater) UpdateDNS(domain string, certPEM []byte) error {
	isWildcard := strings.HasPrefix(domain, "*.")
	baseDomain := strings.TrimPrefix(domain, "*.")

	keyCfg, ok := u.keys.keyFor(baseDomain)
	if !ok {
		log.Warn().Str("domain", domain).Msg("No TSIG key configured for domain — skipping DNS UPDATE")
		return nil
	}

	nameserver, zoneApex, err := u.resolveTarget(baseDomain, keyCfg)
	if err != nil {
		return fmt.Errorf("resolve DNS UPDATE target for %s: %w", domain, err)
	}

	issuer := u.cfg.CAAIssuer
	if issuer == "" {
		issuer = deriveIssuer(u.caURL)
	}

	msg := new(dns.Msg)
	msg.SetUpdate(zoneApex)

	msg.RemoveRRset([]dns.RR{&dns.CAA{Hdr: dns.RR_Header{
		Name: dns.Fqdn(zoneApex), Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 0,
	}}})
	msg.Insert(buildCAARecords(zoneApex, issuer, u.accountURI, u.cfg.CAAIodef, u.cfg.TTL))

	if !isWildcard {
		cert, err := parseCertPEM(certPEM)
		if err != nil {
			return fmt.Errorf("parse certificate PEM: %w", err)
		}
		tlsaHex, err := GenerateTLSA(cert)
		if err != nil {
			return fmt.Errorf("generate TLSA: %w", err)
		}
		tlsaName := fmt.Sprintf("_%d._%s.%s", u.cfg.TLSAPort, u.cfg.TLSAProto, dns.Fqdn(baseDomain))

		msg.RemoveRRset([]dns.RR{&dns.TLSA{Hdr: dns.RR_Header{
			Name: tlsaName, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 0,
		}}})
		msg.Insert([]dns.RR{&dns.TLSA{
			Hdr:          dns.RR_Header{Name: tlsaName, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: u.cfg.TTL},
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Certificate:  tlsaHex,
		}})
	}

	if err := u.sendUpdate(msg, keyCfg, nameserver); err != nil {
		return err
	}

	log.Info().
		Str("domain", domain).
		Str("nameserver", nameserver).
		Str("zone", zoneApex).
		Bool("tlsa", !isWildcard).
		Msg("DNS UPDATE successful")

	return nil
}

// AddTLSA adds a TLSA record without removing existing ones.
// Used during TLSA pre-publish rollover to publish the new TLSA alongside the old.
func (u *Updater) AddTLSA(domain, tlsaHex string) error {
	keyCfg, ok := u.keys.keyFor(domain)
	if !ok {
		log.Warn().Str("domain", domain).Msg("No TSIG key configured — skipping AddTLSA")
		return nil
	}
	nameserver, zoneApex, err := u.resolveTarget(domain, keyCfg)
	if err != nil {
		return fmt.Errorf("resolve DNS UPDATE target for %s: %w", domain, err)
	}

	tlsaName := fmt.Sprintf("_%d._%s.%s", u.cfg.TLSAPort, u.cfg.TLSAProto, dns.Fqdn(domain))
	msg := new(dns.Msg)
	msg.SetUpdate(zoneApex)
	msg.Insert([]dns.RR{&dns.TLSA{
		Hdr:          dns.RR_Header{Name: tlsaName, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: u.cfg.TTL},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  tlsaHex,
	}})
	return u.sendUpdate(msg, keyCfg, nameserver)
}

// RemoveTLSA removes a specific TLSA record by its hex value.
// Used during rollover cleanup to remove the old TLSA after the sync lag has elapsed.
func (u *Updater) RemoveTLSA(domain, tlsaHex string) error {
	if tlsaHex == "" {
		return nil
	}
	keyCfg, ok := u.keys.keyFor(domain)
	if !ok {
		return nil
	}
	nameserver, zoneApex, err := u.resolveTarget(domain, keyCfg)
	if err != nil {
		return fmt.Errorf("resolve DNS UPDATE target for %s: %w", domain, err)
	}

	tlsaName := fmt.Sprintf("_%d._%s.%s", u.cfg.TLSAPort, u.cfg.TLSAProto, dns.Fqdn(domain))
	msg := new(dns.Msg)
	msg.SetUpdate(zoneApex)
	// Remove specific RR (class ANY + matching rdata removes only the matching record).
	msg.Remove([]dns.RR{&dns.TLSA{
		Hdr:          dns.RR_Header{Name: tlsaName, Rrtype: dns.TypeTLSA, Class: dns.ClassNONE, Ttl: 0},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  tlsaHex,
	}})
	return u.sendUpdate(msg, keyCfg, nameserver)
}

// UpdateCAA replaces CAA records at the zone apex for domain.
func (u *Updater) UpdateCAA(domain string) error {
	keyCfg, ok := u.keys.keyFor(domain)
	if !ok {
		return nil
	}
	nameserver, zoneApex, err := u.resolveTarget(domain, keyCfg)
	if err != nil {
		return fmt.Errorf("resolve DNS UPDATE target for %s: %w", domain, err)
	}

	issuer := u.cfg.CAAIssuer
	if issuer == "" {
		issuer = deriveIssuer(u.caURL)
	}

	msg := new(dns.Msg)
	msg.SetUpdate(zoneApex)
	msg.RemoveRRset([]dns.RR{&dns.CAA{Hdr: dns.RR_Header{
		Name: dns.Fqdn(zoneApex), Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 0,
	}}})
	msg.Insert(buildCAARecords(zoneApex, issuer, u.accountURI, u.cfg.CAAIodef, u.cfg.TTL))
	return u.sendUpdate(msg, keyCfg, nameserver)
}

// sendUpdate signs msg with TSIG and sends it via TCP to nameserver.
func (u *Updater) sendUpdate(msg *dns.Msg, keyCfg DomainKeyConfig, nameserver string) error {
	msg.SetTsig(keyCfg.TSIGKeyName, keyCfg.TSIGAlgorithm, 300, time.Now().Unix())

	c := new(dns.Client)
	c.Net = "tcp"
	c.TsigSecret = map[string]string{keyCfg.TSIGKeyName: keyCfg.TSIGKeySecret}

	resp, _, err := c.Exchange(msg, nameserver)
	if err != nil {
		return fmt.Errorf("DNS UPDATE to %s: %w", nameserver, err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS UPDATE rejected by %s: %s", nameserver, dns.RcodeToString[resp.Rcode])
	}
	return nil
}

// resolveTarget returns the nameserver address (host:port) and zone apex (FQDN).
// Both keyCfg overrides set → skip SOA walk entirely.
func (u *Updater) resolveTarget(domain string, keyCfg DomainKeyConfig) (nameserver, zoneApex string, err error) {
	if keyCfg.Nameserver != "" && keyCfg.ZoneApex != "" {
		return normalizeAddr(keyCfg.Nameserver), dns.Fqdn(keyCfg.ZoneApex), nil
	}

	soaNS, soaApex, err := findAuthNS(domain, "")
	if err != nil {
		return "", "", err
	}

	if keyCfg.Nameserver != "" {
		nameserver = normalizeAddr(keyCfg.Nameserver)
	} else {
		nameserver = normalizeAddr(strings.TrimSuffix(soaNS, "."))
	}
	if keyCfg.ZoneApex != "" {
		zoneApex = dns.Fqdn(keyCfg.ZoneApex)
	} else {
		zoneApex = soaApex
	}
	return nameserver, zoneApex, nil
}

func normalizeAddr(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "53")
	}
	return addr
}

func parseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}
