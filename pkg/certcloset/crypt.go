package certcloset

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/go-acme/lego/v4/certificate"
)

var gcmEnvelopeMagic = []byte("TAS3G1")

// PKCS#7 Padding
func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func unpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	padding := int(data[len(data)-1])
	if padding <= 0 || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padding], nil
}

func encryptAES(key []byte, text []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("the key length must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("unable to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to create GCM cipher: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("unable to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, text, nil)
	out := make([]byte, 0, len(gcmEnvelopeMagic)+len(nonce)+len(ciphertext))
	out = append(out, gcmEnvelopeMagic...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptAES(key []byte, text []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("the key length must be 32 bytes")
	}
	if len(text) >= len(gcmEnvelopeMagic) && bytes.Equal(text[:len(gcmEnvelopeMagic)], gcmEnvelopeMagic) {
		return decryptAESGCM(key, text[len(gcmEnvelopeMagic):])
	}
	return decryptAESLegacyCBC(key, text)
}

func decryptAESGCM(key []byte, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("unable to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to create GCM cipher: %w", err)
	}
	if len(payload) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	nonce := payload[:gcm.NonceSize()]
	ciphertext := payload[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt GCM ciphertext: %w", err)
	}
	return plain, nil
}

func decryptAESLegacyCBC(key []byte, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("unable to create AES cipher: %w", err)
	}
	if len(text) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	if len(text)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(text, text)
	return unpadPKCS7(text)
}

// deriveKey produces a 32-byte AES-256 key from the configured password
// using SHA-256 so any password length is accepted.
func (c *CertCloset) deriveKey() []byte {
	h := sha256.Sum256([]byte(c.config.Password))
	return h[:]
}

func (c *CertCloset) encryptPrivKey(cert certificate.Resource) ([]byte, error) {
	encryptedPrivKey, err := encryptAES(c.deriveKey(), cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt the private key: %w", err)
	}

	return encryptedPrivKey, nil
}

func (c *CertCloset) decryptPrivKey(encryptedPrivKey []byte) ([]byte, error) {
	privKey, err := decryptAES(c.deriveKey(), encryptedPrivKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt the private key: %w", err)
	}

	return privKey, nil
}
