package dnsupdate

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func startUDPServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	addr := pc.LocalAddr().String()
	srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: handler}
	go srv.ActivateAndServe() //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown() }) //nolint:errcheck
	return addr
}

func TestFindAuthNS_SOAInAnswer(t *testing.T) {
	const (
		testMNAME = "ns1.example.com."
		testApex  = "example.com."
	)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		// Only answer SOA for the apex; return NODATA for anything else to force label strip.
		if q.Qtype == dns.TypeSOA && q.Name == testApex {
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr:     dns.RR_Header{Name: testApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:      testMNAME,
				Mbox:    "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 300,
			})
		}
		w.WriteMsg(m) //nolint:errcheck
	})

	addr := startUDPServer(t, mux)

	ns, apex, err := findAuthNS("foo.bar.example.com", addr)
	if err != nil {
		t.Fatalf("findAuthNS: %v", err)
	}
	if ns != testMNAME {
		t.Errorf("nameserver: want %q got %q", testMNAME, ns)
	}
	if apex != testApex {
		t.Errorf("zone apex: want %q got %q", testApex, apex)
	}
}

func TestFindAuthNS_SOAInAuthority(t *testing.T) {
	const (
		testMNAME = "ns1.example.com."
		testApex  = "example.com."
	)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// Return SOA in Ns (authority) section — simulates recursive resolver response.
		if r.Question[0].Qtype == dns.TypeSOA {
			m.Ns = append(m.Ns, &dns.SOA{
				Hdr:     dns.RR_Header{Name: testApex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:      testMNAME,
				Mbox:    "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 300,
			})
		}
		w.WriteMsg(m) //nolint:errcheck
	})

	addr := startUDPServer(t, mux)

	ns, apex, err := findAuthNS("sub.example.com", addr)
	if err != nil {
		t.Fatalf("findAuthNS: %v", err)
	}
	if ns != testMNAME {
		t.Errorf("nameserver: want %q got %q", testMNAME, ns)
	}
	if apex != testApex {
		t.Errorf("zone apex: want %q got %q", testApex, apex)
	}
}

func TestFindAuthNS_NoSOA(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m) //nolint:errcheck
	})

	addr := startUDPServer(t, mux)

	_, _, err := findAuthNS("example.com", addr)
	if err == nil {
		t.Fatal("expected error when no SOA is found")
	}
}
