package traefikclient

import "testing"

func TestParseRuleDoubleQuotes(t *testing.T) {
	r := TraefikRouter{Rule: `Host("foo.bar")`}
	if got := r.ParseRule(); got != "foo.bar" {
		t.Errorf("want %q got %q", "foo.bar", got)
	}
}

func TestParseRuleBacktick(t *testing.T) {
	r := TraefikRouter{Rule: "Host(`foo.bar`)"}
	if got := r.ParseRule(); got != "foo.bar" {
		t.Errorf("want %q got %q", "foo.bar", got)
	}
}

func TestParseRuleSingleQuote(t *testing.T) {
	r := TraefikRouter{Rule: `Host('foo.bar')`}
	if got := r.ParseRule(); got != "foo.bar" {
		t.Errorf("want %q got %q", "foo.bar", got)
	}
}

func TestParseRuleNoMatch(t *testing.T) {
	r := TraefikRouter{Rule: `PathPrefix("/api")`}
	if got := r.ParseRule(); got != "" {
		t.Errorf("want empty string got %q", got)
	}
}

func TestParseRuleEmpty(t *testing.T) {
	r := TraefikRouter{Rule: ""}
	if got := r.ParseRule(); got != "" {
		t.Errorf("want empty string got %q", got)
	}
}

func TestParseRuleSubdomain(t *testing.T) {
	r := TraefikRouter{Rule: `Host("api.example.com")`}
	if got := r.ParseRule(); got != "api.example.com" {
		t.Errorf("want %q got %q", "api.example.com", got)
	}
}

func TestParseDomainsMultipleHosts(t *testing.T) {
	r := TraefikRouter{Rule: `Host("a.example.com","b.example.com")`}
	got := r.ParseDomains()
	if len(got) != 2 {
		t.Fatalf("want 2 domains got %d: %v", len(got), got)
	}
	if got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("unexpected domains: %v", got)
	}
}
