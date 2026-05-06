package buckcert

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
)

func TestCreateUserCreatesNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	u, err := CreateUser("new@example.com", path)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Email != "new@example.com" {
		t.Errorf("email want %q got %q", "new@example.com", u.Email)
	}
	if len(u.Key) == 0 {
		t.Fatal("key must not be empty")
	}
	if u.Registration != nil {
		t.Fatal("new user must have nil registration")
	}
}

func TestCreateUserLoadsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")

	u1, err := CreateUser("existing@example.com", path)
	if err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	if err := SaveUser(u1, path); err != nil {
		t.Fatalf("SaveUser: %v", err)
	}

	u2, err := CreateUser("existing@example.com", path)
	if err != nil {
		t.Fatalf("second CreateUser: %v", err)
	}
	if string(u2.Key) != string(u1.Key) {
		t.Error("second CreateUser must return same key as saved user")
	}
}

func TestSaveLoadUserRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	u, err := CreateUser("roundtrip@example.com", path)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := SaveUser(u, path); err != nil {
		t.Fatalf("SaveUser: %v", err)
	}

	got, err := LoadUser(path)
	if err != nil {
		t.Fatalf("LoadUser: %v", err)
	}
	if got.Email != u.Email {
		t.Errorf("email want %q got %q", u.Email, got.Email)
	}
	if string(got.Key) != string(u.Key) {
		t.Error("key mismatch after save/load")
	}
}

func TestLoadUserNotExist(t *testing.T) {
	_, err := LoadUser("/does/not/exist/user.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadUserCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	if err := os.WriteFile(path, []byte("not json {{{"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadUser(path)
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
}

func TestSaveUserFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	u, _ := CreateUser("perm@example.com", path)
	if err := SaveUser(u, path); err != nil {
		t.Fatalf("SaveUser: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions want 0600 got %o", info.Mode().Perm())
	}
}

func TestGetPrivateKeyParseable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	u, err := CreateUser("key@example.com", path)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// GetPrivateKey calls log.Fatal on parse error — verify key is valid PEM first
	key, err2 := certcrypto.ParsePEMPrivateKey(u.Key)
	if err2 != nil {
		t.Fatalf("key PEM must be parseable: %v", err2)
	}
	if key == nil {
		t.Fatal("parsed key is nil")
	}
}
