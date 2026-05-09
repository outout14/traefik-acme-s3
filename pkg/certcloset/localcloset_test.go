package certcloset

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewLocalCertClosetCreatesIndexFile(t *testing.T) {
	dir := t.TempDir()
	_, err := NewLocalCertCloset(Config{}, dir)
	if err != nil {
		t.Fatalf("NewLocalCertCloset: %v", err)
	}
	idxPath := filepath.Join(dir, CerticateIndexFile)
	if _, err := os.Stat(idxPath); os.IsNotExist(err) {
		t.Fatal("index file not created")
	}
}

func TestLocalCertClosetIndexRoundTrip(t *testing.T) {
	dir := t.TempDir()
	lc, err := NewLocalCertCloset(Config{}, dir)
	if err != nil {
		t.Fatalf("NewLocalCertCloset: %v", err)
	}

	exp := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	lc.GetIndex().Add(CertificateEntry{Domain: "save.com", ExpirationDate: exp})
	if err := lc.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	lc2, err := NewLocalCertCloset(Config{}, dir)
	if err != nil {
		t.Fatalf("reload NewLocalCertCloset: %v", err)
	}
	entry, ok := lc2.GetIndex().CertIndex["save.com"]
	if !ok {
		t.Fatal("entry not found after reload")
	}
	if !entry.ExpirationDate.Equal(exp) {
		t.Errorf("expiry want %v got %v", exp, entry.ExpirationDate)
	}
}

func TestLocalCertClosetCheckIntegrityMissingFile(t *testing.T) {
	dir := t.TempDir()
	lc, err := NewLocalCertCloset(Config{}, dir)
	if err != nil {
		t.Fatalf("NewLocalCertCloset: %v", err)
	}

	// Add index entry without creating the actual cert file
	lc.GetIndex().Add(CertificateEntry{Domain: "missing.com", ExpirationDate: time.Now()})
	if err := lc.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	failed := lc.CheckIntegrity()
	if len(failed) != 1 || failed[0].Domain != "missing.com" {
		t.Fatalf("want 1 integrity failure for missing.com, got %v", failed)
	}
}

func TestLocalCertClosetCheckIntegrityAllPresent(t *testing.T) {
	dir := t.TempDir()
	lc, err := NewLocalCertCloset(Config{}, dir)
	if err != nil {
		t.Fatalf("NewLocalCertCloset: %v", err)
	}

	// Create cert and key files for the cert domain.
	certDir := filepath.Join(dir, "ok.com")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, localCertFile), []byte("CERT"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, localKeyFile), []byte("KEY"), 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	lc.GetIndex().Add(CertificateEntry{Domain: "ok.com", ExpirationDate: time.Now()})

	failed := lc.CheckIntegrity()
	if len(failed) != 0 {
		t.Fatalf("want 0 failures got %v", failed)
	}
}

func TestLocalCertClosetCheckIntegrityMissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	lc, err := NewLocalCertCloset(Config{}, dir)
	if err != nil {
		t.Fatalf("NewLocalCertCloset: %v", err)
	}

	certDir := filepath.Join(dir, "missing-key.com")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, localCertFile), []byte("CERT"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	lc.GetIndex().Add(CertificateEntry{Domain: "missing-key.com", ExpirationDate: time.Now()})
	failed := lc.CheckIntegrity()
	if len(failed) != 1 || failed[0].Domain != "missing-key.com" {
		t.Fatalf("want 1 integrity failure for missing-key.com, got %v", failed)
	}
}

func TestNewLocalCertClosetPathNotExist(t *testing.T) {
	_, err := NewLocalCertCloset(Config{}, "/does/not/exist/path")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}
