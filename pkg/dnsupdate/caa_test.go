package dnsupdate

import (
	"testing"

	"github.com/miekg/dns"
)

func TestDeriveIssuer(t *testing.T) {
	tests := []struct {
		caURL  string
		issuer string
	}{
		{"https://acme-v02.api.letsencrypt.org/directory", "letsencrypt.org"},
		{"https://acme-staging-v02.api.letsencrypt.org/directory", "letsencrypt.org"},
		{"https://api.buypass.com/acme/directory", "buypass.com"},
		{"https://acme.zerossl.com/v2/DV90", "zerossl.com"},
		{"https://acme.sectigo.com/v2/DV", "sectigo.com"},
		{"https://acme.example.org/dir", "example.org"},
		{"https://ca.internal/dir", "ca.internal"},
		{"not-a-url", ""},
	}
	for _, tt := range tests {
		got := deriveIssuer(tt.caURL)
		if got != tt.issuer {
			t.Errorf("deriveIssuer(%q) = %q, want %q", tt.caURL, got, tt.issuer)
		}
	}
}

func TestBuildCAARecords_WithIodef(t *testing.T) {
	records := buildCAARecords("example.com.", "letsencrypt.org", "", "mailto:ops@example.com", 300)
	if len(records) != 3 {
		t.Fatalf("want 3 records (issue+issuewild+iodef), got %d", len(records))
	}
	assertCAA(t, records[0], "issue", "letsencrypt.org", "example.com.", 300)
	assertCAA(t, records[1], "issuewild", "letsencrypt.org", "example.com.", 300)
	assertCAA(t, records[2], "iodef", "mailto:ops@example.com", "example.com.", 300)
}

func TestBuildCAARecords_NoIodef(t *testing.T) {
	records := buildCAARecords("example.com", "letsencrypt.org", "", "", 600)
	if len(records) != 2 {
		t.Fatalf("want 2 records (issue+issuewild), got %d", len(records))
	}
	assertCAA(t, records[0], "issue", "letsencrypt.org", "example.com.", 600)
	assertCAA(t, records[1], "issuewild", "letsencrypt.org", "example.com.", 600)
}

func TestBuildCAARecords_FlagZero(t *testing.T) {
	records := buildCAARecords("example.com.", "letsencrypt.org", "", "", 300)
	for _, rr := range records {
		caa := rr.(*dns.CAA)
		if caa.Flag != 0 {
			t.Errorf("CAA flag must be 0, got %d", caa.Flag)
		}
	}
}

func TestBuildCAARecords_WithAccountURI(t *testing.T) {
	const acctURI = "https://acme-v02.api.letsencrypt.org/acme/acct/12345678"
	records := buildCAARecords("example.com.", "letsencrypt.org", acctURI, "", 300)
	if len(records) != 2 {
		t.Fatalf("want 2 records, got %d", len(records))
	}
	want := "letsencrypt.org; accounturi=" + acctURI
	assertCAA(t, records[0], "issue", want, "example.com.", 300)
	assertCAA(t, records[1], "issuewild", want, "example.com.", 300)
}

func TestIssuerWithAccount(t *testing.T) {
	tests := []struct {
		issuer     string
		accountURI string
		want       string
	}{
		{"letsencrypt.org", "", "letsencrypt.org"},
		{"letsencrypt.org", "https://acme-v02.api.letsencrypt.org/acme/acct/99", "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/99"},
	}
	for _, tt := range tests {
		got := issuerWithAccount(tt.issuer, tt.accountURI)
		if got != tt.want {
			t.Errorf("issuerWithAccount(%q, %q) = %q, want %q", tt.issuer, tt.accountURI, got, tt.want)
		}
	}
}

func assertCAA(t *testing.T, rr dns.RR, tag, value, name string, ttl uint32) {
	t.Helper()
	caa, ok := rr.(*dns.CAA)
	if !ok {
		t.Fatalf("want *dns.CAA, got %T", rr)
	}
	if caa.Tag != tag {
		t.Errorf("CAA tag: want %q got %q", tag, caa.Tag)
	}
	if caa.Value != value {
		t.Errorf("CAA value: want %q got %q", value, caa.Value)
	}
	if caa.Hdr.Name != name {
		t.Errorf("CAA name: want %q got %q", name, caa.Hdr.Name)
	}
	if caa.Hdr.Ttl != ttl {
		t.Errorf("CAA TTL: want %d got %d", ttl, caa.Hdr.Ttl)
	}
}
