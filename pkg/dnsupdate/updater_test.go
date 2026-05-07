package dnsupdate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

const (
	testKeyName = "update.example.com."
	testZone    = "example.com."
)

// startTCPServer starts a miekg/dns TCP server that records received UPDATE messages.
// It returns NOERROR for all requests without verifying TSIG — tests inspect the
// recorded messages to verify the client sent a properly signed UPDATE.
func startTCPServer(t *testing.T, received *[]*dns.Msg, mu *sync.Mutex) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		mu.Lock()
		cp := r.Copy()
		*received = append(*received, cp)
		mu.Unlock()

		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeSuccess
		w.WriteMsg(m) //nolint:errcheck
	})

	srv := &dns.Server{
		Listener: ln,
		Net:      "tcp",
		Handler:  mux,
		// DefaultMsgAcceptFunc rejects OpcodeUpdate; override to allow it.
		MsgAcceptFunc: func(dh dns.Header) dns.MsgAcceptAction {
			opcode := int(dh.Bits>>11) & 0xF
			if opcode == dns.OpcodeUpdate {
				return dns.MsgAccept
			}
			return dns.DefaultMsgAcceptFunc(dh)
		},
	}
	go srv.ActivateAndServe() //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown() }) //nolint:errcheck
	return addr
}

// genTSIGKey returns a random base64-encoded 32-byte HMAC key.
func genTSIGKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// makeCertPEM returns PEM-encoded cert bytes for an EC P-256 key and given CN.
func makeCertPEM(t *testing.T, cn string) ([]byte, interface{}) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeSelfSignedCert(t, &key.PublicKey, key, cn)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return pemBytes, cert
}

func newTestUpdater(addr, secret string) *Updater {
	return &Updater{
		cfg: Config{
			Enabled:   true,
			TTL:       300,
			TLSAPort:  443,
			TLSAProto: "tcp",
		},
		keys: keyMap{
			"example.com": DomainKeyConfig{
				TSIGKeyName:   testKeyName,
				TSIGKeySecret: secret,
				TSIGAlgorithm: dns.HmacSHA256,
				Nameserver:    addr,
				ZoneApex:      "example.com",
			},
		},
		caURL:      "https://acme-v02.api.letsencrypt.org/directory",
		accountURI: "https://acme-v02.api.letsencrypt.org/acme/acct/12345678",
	}
}

func TestUpdaterUpdateDNS_Success(t *testing.T) {
	secret := genTSIGKey(t)
	var received []*dns.Msg
	var mu sync.Mutex

	addr := startTCPServer(t, &received, &mu)
	certPEM, _ := makeCertPEM(t, "test.example.com")

	u := newTestUpdater(addr, secret)
	if err := u.UpdateDNS("test.example.com", certPEM); err != nil {
		t.Fatalf("UpdateDNS: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("want 1 UPDATE message, got %d", len(received))
	}
	msg := received[0]

	if msg.IsTsig() == nil {
		t.Error("UPDATE message must carry TSIG")
	}

	var hasTLSA, hasCAAIssue, hasCAAIssuewild bool
	for _, rr := range msg.Ns {
		switch r := rr.(type) {
		case *dns.TLSA:
			if r.Hdr.Class == dns.ClassINET {
				hasTLSA = true
				if r.Usage != 3 || r.Selector != 1 || r.MatchingType != 1 {
					t.Errorf("TLSA params: want 3 1 1, got %d %d %d", r.Usage, r.Selector, r.MatchingType)
				}
				if len(r.Certificate) != 64 { // 32 bytes → 64 hex chars
					t.Errorf("TLSA hex: want 64 chars, got %d", len(r.Certificate))
				}
				wantName := "_443._tcp.test.example.com."
				if r.Hdr.Name != wantName {
					t.Errorf("TLSA name: want %q got %q", wantName, r.Hdr.Name)
				}
			}
		case *dns.CAA:
			if r.Hdr.Class == dns.ClassINET {
				switch r.Tag {
				case "issue":
					hasCAAIssue = true
					wantVal := "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345678"
					if r.Value != wantVal {
						t.Errorf("CAA issue value:\n  got  %q\n  want %q", r.Value, wantVal)
					}
				case "issuewild":
					hasCAAIssuewild = true
				}
			}
		}
	}

	if !hasTLSA {
		t.Error("UPDATE must include TLSA record")
	}
	if !hasCAAIssue {
		t.Error("UPDATE must include CAA issue record")
	}
	if !hasCAAIssuewild {
		t.Error("UPDATE must include CAA issuewild record")
	}
}

func TestUpdaterUpdateDNS_Wildcard_SkipsTLSA(t *testing.T) {
	secret := genTSIGKey(t)
	var received []*dns.Msg
	var mu sync.Mutex

	addr := startTCPServer(t, &received, &mu)

	u := newTestUpdater(addr, secret)
	// wildcard cert — no real PEM needed since TLSA path is skipped
	if err := u.UpdateDNS("*.example.com", []byte("unused-for-wildcard")); err != nil {
		t.Fatalf("UpdateDNS: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("want 1 UPDATE message, got %d", len(received))
	}
	for _, rr := range received[0].Ns {
		if _, ok := rr.(*dns.TLSA); ok && rr.Header().Class == dns.ClassINET {
			t.Error("wildcard update must not include TLSA records")
		}
	}
}

func TestUpdaterUpdateDNS_NoKey(t *testing.T) {
	u := &Updater{
		cfg:   Config{Enabled: true, TTL: 300, TLSAPort: 443, TLSAProto: "tcp"},
		keys:  keyMap{}, // empty — no key for any domain
		caURL: "https://acme-v02.api.letsencrypt.org/directory",
	}
	// Must return nil (not an error) when no key is configured.
	if err := u.UpdateDNS("nope.example.com", []byte("cert")); err != nil {
		t.Fatalf("want nil error, got: %v", err)
	}
}

func TestUpdaterUpdateDNS_ServerRefused(t *testing.T) {
	secret := genTSIGKey(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m) //nolint:errcheck
	})
	srv := &dns.Server{
		Listener: ln, Net: "tcp", Handler: mux,
		MsgAcceptFunc: func(dh dns.Header) dns.MsgAcceptAction {
			if int(dh.Bits>>11)&0xF == dns.OpcodeUpdate {
				return dns.MsgAccept
			}
			return dns.DefaultMsgAcceptFunc(dh)
		},
	}
	go srv.ActivateAndServe() //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown() }) //nolint:errcheck

	certPEM, _ := makeCertPEM(t, "test.example.com")
	u := newTestUpdater(addr, secret)

	if err := u.UpdateDNS("test.example.com", certPEM); err == nil {
		t.Fatal("want error on REFUSED response, got nil")
	}
}

func TestKeyMapKeyFor(t *testing.T) {
	km := keyMap{
		"example.com":     {TSIGKeyName: "zone-key"},
		"sub.example.com": {TSIGKeyName: "sub-key"},
	}

	tests := []struct {
		domain  string
		wantKey string
		wantOK  bool
	}{
		{"example.com", "zone-key", true},
		{"foo.example.com", "zone-key", true},        // inherits from parent
		{"deep.foo.example.com", "zone-key", true},   // inherits from grandparent
		{"sub.example.com", "sub-key", true},          // exact match takes priority
		{"child.sub.example.com", "sub-key", true},    // inherits from sub
		{"other.org", "", false},
	}
	for _, tt := range tests {
		cfg, ok := km.keyFor(tt.domain)
		if ok != tt.wantOK {
			t.Errorf("keyFor(%q): ok=%v want %v", tt.domain, ok, tt.wantOK)
			continue
		}
		if ok && cfg.TSIGKeyName != tt.wantKey {
			t.Errorf("keyFor(%q): key=%q want %q", tt.domain, cfg.TSIGKeyName, tt.wantKey)
		}
	}
}
