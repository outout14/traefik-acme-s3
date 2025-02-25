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

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("unable to generate IV: %w", err)
	}

	text = padPKCS7(text, aes.BlockSize)

	ciphertext := make([]byte, len(text))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, text)

	return append(iv, ciphertext...), nil
}

func decryptAES(key []byte, text []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("the key length must be 32 bytes")
	}

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

func (c *CertCloset) encryptPrivKey(cert certificate.Resource) ([]byte, error) {
	encryptedPrivKey, err := encryptAES([]byte(c.config.Password), cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt the private key: %w", err)
	}

	return encryptedPrivKey, nil
}

func (c *CertCloset) decryptPrivKey(encryptedPrivKey []byte) ([]byte, error) {
	privKey, err := decryptAES([]byte(c.config.Password), encryptedPrivKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt the private key: %w", err)
	}

	return privKey, nil
}
