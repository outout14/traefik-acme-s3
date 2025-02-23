package certcloset

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/go-acme/lego/v4/certificate"
)

// I don't know anything about encryption, so it might be a good idea to look at the code haha.

func encryptAES(key []byte, text []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("the key length must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("unable to create AES cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("unable to generate IV: %w", err)
	}

	padding := aes.BlockSize - len(text)%aes.BlockSize
	text = append(text, bytes.Repeat([]byte{byte(padding)}, padding)...)

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(text))
	mode.CryptBlocks(ciphertext, text)

	return ciphertext, nil
}

func decryptAES(key []byte, text []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("the key length must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("unable to create AES cipher: %w", err)
	}

	if len(text)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(text, text)

	padding := int(text[len(text)-1])
	text = text[:len(text)-padding]

	return text, nil
}

func (c *CertCloset) encryptPrivKey(cert certificate.Resource) ([]byte, error) {
	privKey := cert.PrivateKey

	// Encrypt the private key
	encryptedPrivKey, err := encryptAES([]byte(c.config.Password), privKey)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt the private key: %w", err)
	}

	return encryptedPrivKey, nil
}
