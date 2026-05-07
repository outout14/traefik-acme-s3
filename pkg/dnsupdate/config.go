package dnsupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// DomainKeyConfig holds TSIG and nameserver settings for one zone.
type DomainKeyConfig struct {
	TSIGKeyName   string `json:"tsig_key_name"`
	TSIGKeySecret string `json:"tsig_key_secret"`  // base64-encoded HMAC secret
	TSIGAlgorithm string `json:"tsig_algorithm"`    // e.g. "hmac-sha256." — defaults to hmac-sha256
	Nameserver    string `json:"nameserver"`         // optional "host:port" override for UPDATE target
	ZoneApex      string `json:"zone_apex"`          // optional zone apex override; skips SOA walk when set alongside Nameserver
}

// Config is embedded in RenewConfig and drives DNS UPDATE behaviour.
type Config struct {
	Enabled         bool   `env:"DNS_UPDATE_ENABLED"          default:"false" help:"Enable DNS UPDATE (RFC 2136) after certificate renewal."`
	KeysFile        string `env:"DNS_UPDATE_KEYS_FILE"        default:""      help:"Path to JSON file mapping domain → TSIG key config."`
	TTL             uint32 `env:"DNS_UPDATE_TTL"              default:"300"   help:"TTL for TLSA and CAA records."`
	TLSAPort        uint16 `env:"DNS_UPDATE_TLSA_PORT"        default:"443"   help:"Port label in TLSA record name (_PORT._PROTO.domain)."`
	TLSAProto       string `env:"DNS_UPDATE_TLSA_PROTO"       default:"tcp"   help:"Protocol label in TLSA record name."`
	CAAIssuer       string `env:"DNS_UPDATE_CAA_ISSUER"       default:""      help:"CAA issuer value. Empty = derived from ACME CA URL."`
	CAAIodef        string `env:"DNS_UPDATE_CAA_IODEF"        default:""      help:"CAA iodef value (e.g. mailto:ops@example.com). Empty = omit iodef record."`
	RolloverEnabled bool   `env:"DNS_UPDATE_ROLLOVER_ENABLED" default:"true"  help:"Enable TLSA pre-publish rollover. When false, TLSA is replaced atomically (gap risk)."`
	TLSATTLSeconds  int    `env:"DNS_UPDATE_TLSA_TTL_SECONDS" default:"3600"  help:"Seconds to wait after pre-publishing new TLSA before switching the certificate."`
	SyncLagSeconds  int    `env:"DNS_UPDATE_SYNC_LAG_SECONDS" default:"300"   help:"Seconds to wait after cert switch before removing the old TLSA record."`
}

type keyMap map[string]DomainKeyConfig

func loadKeysFile(path string) (keyMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keys file: %w", err)
	}
	var m keyMap
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse keys file: %w", err)
	}
	for k, v := range m {
		if v.TSIGAlgorithm == "" {
			v.TSIGAlgorithm = dns.HmacSHA256
			m[k] = v
		}
	}
	return m, nil
}

// keyFor returns the DomainKeyConfig for domain using longest-match parent walk.
// e.g. "sub.example.com" matches key "example.com" if no exact entry exists.
func (km keyMap) keyFor(domain string) (DomainKeyConfig, bool) {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for d != "" {
		if cfg, ok := km[d]; ok {
			return cfg, true
		}
		dot := strings.IndexByte(d, '.')
		if dot < 0 {
			break
		}
		d = d[dot+1:]
	}
	return DomainKeyConfig{}, false
}
