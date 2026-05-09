package buckcert

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
)

type memoryUserStore struct {
	data              []byte
	exists            bool
	forceAlreadyExist bool
}

func (m *memoryUserStore) LoadACMEUser() ([]byte, bool, error) {
	if !m.exists {
		return nil, false, nil
	}
	return append([]byte(nil), m.data...), true, nil
}

func (m *memoryUserStore) StoreACMEUser(data []byte) error {
	m.data = append([]byte(nil), data...)
	m.exists = true
	return nil
}

func (m *memoryUserStore) StoreACMEUserIfNotExists(data []byte) (bool, error) {
	if m.forceAlreadyExist || m.exists {
		return false, nil
	}
	return true, m.StoreACMEUser(data)
}

type racingUserStore struct {
	data      []byte
	loadCount int
}

func (r *racingUserStore) LoadACMEUser() ([]byte, bool, error) {
	r.loadCount++
	if r.loadCount == 1 {
		return nil, false, nil
	}
	return append([]byte(nil), r.data...), true, nil
}

func (r *racingUserStore) StoreACMEUser(data []byte) error {
	r.data = append([]byte(nil), data...)
	return nil
}

func (r *racingUserStore) StoreACMEUserIfNotExists(_ []byte) (bool, error) {
	return false, nil
}

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

func TestCreateUserDoesNotOverwriteCorruptExistingUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	if err := os.WriteFile(path, []byte("not json {{{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateUser("new@example.com", path); err == nil {
		t.Fatal("expected corrupt existing user to fail")
	}
}

func TestLoadOrCreateUserLoadsS3User(t *testing.T) {
	u, err := newUser("s3@example.com")
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshalUser(u)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryUserStore{data: data, exists: true}

	got, err := LoadOrCreateUser(Config{
		Email:       "ignored@example.com",
		UserKeyPath: filepath.Join(t.TempDir(), "missing.json"),
		UserStore:   store,
	})
	if err != nil {
		t.Fatalf("LoadOrCreateUser: %v", err)
	}
	if got.Email != "s3@example.com" {
		t.Fatalf("loaded S3 user email = %q", got.Email)
	}
}

func TestLoadOrCreateUserImportsLocalUserToS3(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	u, err := newUser("local@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveUser(u, path); err != nil {
		t.Fatal(err)
	}
	store := &memoryUserStore{}

	got, err := LoadOrCreateUser(Config{
		Email:       "ignored@example.com",
		UserKeyPath: path,
		UserStore:   store,
	})
	if err != nil {
		t.Fatalf("LoadOrCreateUser: %v", err)
	}
	if got.Email != "local@example.com" {
		t.Fatalf("loaded local user email = %q", got.Email)
	}

	want, err := marshalUser(u)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(store.data, want) {
		t.Fatal("local user was not stored in S3 store")
	}
}

func TestLoadOrCreateUserCreatesAndStoresS3User(t *testing.T) {
	store := &memoryUserStore{}

	got, err := LoadOrCreateUser(Config{
		Email:       "new-s3@example.com",
		UserKeyPath: filepath.Join(t.TempDir(), "missing.json"),
		UserStore:   store,
	})
	if err != nil {
		t.Fatalf("LoadOrCreateUser: %v", err)
	}
	if got.Email != "new-s3@example.com" {
		t.Fatalf("new user email = %q", got.Email)
	}
	if !store.exists || len(store.data) == 0 {
		t.Fatal("new user was not stored in S3 store")
	}
}

func TestLoadOrCreateUserReloadsConcurrentS3Winner(t *testing.T) {
	winner, err := newUser("winner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshalUser(winner)
	if err != nil {
		t.Fatal(err)
	}
	store := &racingUserStore{data: data}

	got, err := LoadOrCreateUser(Config{
		Email:       "loser@example.com",
		UserKeyPath: filepath.Join(t.TempDir(), "missing.json"),
		UserStore:   store,
	})
	if err != nil {
		t.Fatalf("LoadOrCreateUser: %v", err)
	}
	if got.Email != "winner@example.com" {
		t.Fatalf("expected concurrent winner, got %q", got.Email)
	}
}

func TestLoadUserInvalidKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	if err := os.WriteFile(path, []byte(`{"email":"bad@example.com","key":"not-pem"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUser(path); err == nil {
		t.Fatal("expected invalid ACME user key to fail")
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
