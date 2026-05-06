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
