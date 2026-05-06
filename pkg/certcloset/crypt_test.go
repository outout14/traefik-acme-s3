package certcloset

import (
	"bytes"
	"testing"
)

func TestPadUnpadRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0x01}},
		{"exactly one block", bytes.Repeat([]byte{0xAB}, 16)},
		{"two blocks", bytes.Repeat([]byte{0xCD}, 32)},
		{"arbitrary", []byte("hello world")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			padded := padPKCS7(tc.data, 16)
			if len(padded)%16 != 0 {
				t.Fatalf("padded length %d not multiple of 16", len(padded))
			}
			got, err := unpadPKCS7(padded)
			if err != nil {
				t.Fatalf("unpad: %v", err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Fatalf("want %v got %v", tc.data, got)
			}
		})
	}
}

func TestUnpadInvalidEmpty(t *testing.T) {
	_, err := unpadPKCS7([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestUnpadInvalidPaddingValue(t *testing.T) {
	// last byte = 255, exceeds slice length
	_, err := unpadPKCS7([]byte{0x01, 0xFF})
	if err == nil {
		t.Fatal("expected error for bad padding value")
	}
}

func TestEncryptDecryptAESRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 32)
	plaintext := []byte("this is the private key PEM data")

	ciphertext, err := encryptAES(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext must differ from plaintext")
	}

	got, err := decryptAES(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("want %q got %q", plaintext, got)
	}
}

func TestEncryptAESWrongKeyLength(t *testing.T) {
	_, err := encryptAES([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestDecryptAESWrongKeyLength(t *testing.T) {
	_, err := decryptAES([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestDecryptAESTooShort(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	_, err := decryptAES(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for ciphertext shorter than block size")
	}
}

func TestEncryptProducesRandomIV(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plain := []byte("same plaintext")

	c1, _ := encryptAES(key, plain)
	c2, _ := encryptAES(key, plain)

	// IV is random so ciphertexts differ
	if bytes.Equal(c1, c2) {
		t.Fatal("two encryptions of same plaintext must produce different ciphertexts")
	}
}

func TestDeriveKeyLength(t *testing.T) {
	c := &CertCloset{config: Config{Password: "any password"}}
	k := c.deriveKey()
	if len(k) != 32 {
		t.Fatalf("key length want 32 got %d", len(k))
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	c := &CertCloset{config: Config{Password: "stable"}}
	if !bytes.Equal(c.deriveKey(), c.deriveKey()) {
		t.Fatal("deriveKey must be deterministic")
	}
}
