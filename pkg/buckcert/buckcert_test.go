package buckcert

import (
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
)

func TestParseKeyTypeValid(t *testing.T) {
	cases := []struct {
		input string
		want  certcrypto.KeyType
	}{
		{"P256", certcrypto.EC256},
		{"P384", certcrypto.EC384},
		{"RSA2048", certcrypto.RSA2048},
		{"RSA4096", certcrypto.RSA4096},
		{"RSA8192", certcrypto.RSA8192},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseKeyType(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("want %q got %q", tc.want, got)
			}
		})
	}
}

func TestParseKeyTypeInvalid(t *testing.T) {
	cases := []string{"", "ec256", "rsa", "P521", "UNKNOWN"}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			_, err := parseKeyType(input)
			if err == nil {
				t.Fatalf("want error for %q, got nil", input)
			}
		})
	}
}

func TestGenerateKeyP256(t *testing.T) {
	key, err := generateKey(certcrypto.EC256)
	if err != nil {
		t.Fatalf("generateKey EC256: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestGenerateKeyP384(t *testing.T) {
	key, err := generateKey(certcrypto.EC384)
	if err != nil {
		t.Fatalf("generateKey EC384: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestGenerateKeyRSA2048(t *testing.T) {
	key, err := generateKey(certcrypto.RSA2048)
	if err != nil {
		t.Fatalf("generateKey RSA2048: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestGenerateKeyUnknown(t *testing.T) {
	_, err := generateKey("UNKNOWN")
	if err == nil {
		t.Fatal("expected error for unknown key type")
	}
}
