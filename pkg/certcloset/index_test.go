package certcloset

import (
	"testing"
	"time"
)

func makeList(entries map[string]time.Time) CertificateList {
	cl := CertificateList{CertIndex: make(map[string]CertificateEntry)}
	for domain, exp := range entries {
		cl.CertIndex[domain] = CertificateEntry{Domain: domain, ExpirationDate: exp}
	}
	return cl
}

func TestGetDiffEmptyBothSides(t *testing.T) {
	remote := makeList(nil)
	local := makeList(nil)
	diff := remote.GetDiff(&local)
	if len(diff) != 0 {
		t.Fatalf("want 0 diff entries got %d", len(diff))
	}
}

func TestGetDiffNoDifference(t *testing.T) {
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	remote := makeList(map[string]time.Time{"a.com": exp})
	local := makeList(map[string]time.Time{"a.com": exp})
	diff := remote.GetDiff(&local)
	if len(diff) != 0 {
		t.Fatalf("want 0 diff entries got %d", len(diff))
	}
}

func TestGetDiffExpiryChanged(t *testing.T) {
	remoteExp := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	localExp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	remote := makeList(map[string]time.Time{"a.com": remoteExp})
	local := makeList(map[string]time.Time{"a.com": localExp})
	diff := remote.GetDiff(&local)
	if len(diff) != 1 {
		t.Fatalf("want 1 diff entry got %d", len(diff))
	}
	if diff[0].Domain != "a.com" {
		t.Errorf("wrong domain in diff: %q", diff[0].Domain)
	}
}

func TestGetDiffRemoteHasExtraEntry(t *testing.T) {
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	remote := makeList(map[string]time.Time{"a.com": exp, "b.com": exp})
	local := makeList(map[string]time.Time{"a.com": exp})
	// b.com is in remote but not local → local has zero-value expiry → diff
	diff := remote.GetDiff(&local)
	if len(diff) != 1 {
		t.Fatalf("want 1 diff entry got %d", len(diff))
	}
	if diff[0].Domain != "b.com" {
		t.Errorf("wrong domain in diff: %q", diff[0].Domain)
	}
}

func TestGetDiffLocalHasExtraEntry(t *testing.T) {
	// extra entry only in local → remote doesn't iterate it → 0 diff
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	remote := makeList(nil)
	local := makeList(map[string]time.Time{"a.com": exp})
	diff := remote.GetDiff(&local)
	if len(diff) != 0 {
		t.Fatalf("want 0 diff entries got %d", len(diff))
	}
}

func TestCertificateListAdd(t *testing.T) {
	cl := CertificateList{CertIndex: make(map[string]CertificateEntry)}
	entry := CertificateEntry{Domain: "x.com", ExpirationDate: time.Now()}
	cl.Add(entry)
	if _, ok := cl.CertIndex["x.com"]; !ok {
		t.Fatal("entry not added")
	}
}

func TestCertificateListRemove(t *testing.T) {
	cl := makeList(map[string]time.Time{"x.com": time.Now()})
	cl.Remove("x.com")
	if _, ok := cl.CertIndex["x.com"]; ok {
		t.Fatal("entry not removed")
	}
}

func TestCertificateListRemoveNonExistent(t *testing.T) {
	cl := makeList(nil)
	cl.Remove("ghost.com") // must not panic
}
