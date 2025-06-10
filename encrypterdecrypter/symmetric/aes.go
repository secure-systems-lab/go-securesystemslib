package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

var (
	ErrInvalidKeyLength = errors.New("invalid key length")
	ErrInvalidMode      = errors.New("invalid mode")
)

type AESMode uint8

const (
	GCM AESMode = iota
)

type AESEncrypterDecrypter struct {
	keyID    string
	keyBytes []byte
	mode     AESMode
}

// NewAESEncrypterDecrypterFromSSLibSymmetricKey creates an
// AESEncrypterDecrypter from an SSLibSymmetricKey.
func NewAESEncrypterDecrypterFromSSLibSymmetricKey(key *SSLibSymmetricKey, mode AESMode) (*AESEncrypterDecrypter, error) {
	switch mode {
	case GCM:
		break
	default:
		return nil, ErrInvalidMode
	}

	return &AESEncrypterDecrypter{
		keyID:    key.KeyID,
		keyBytes: key.KeyVal,
		mode:     mode,
	}, nil
}

// Encrypt encrypts the provided data with the key of the AES
// EncrypterDecrypter.
func (ed *AESEncrypterDecrypter) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ed.keyBytes)
	if err != nil {
		return nil, err
	}

	var ciphertext []byte

	switch ed.mode {
	case GCM:
		gcm, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, err
		}

		ciphertext = gcm.Seal(nil, nil, data, nil)
	}
	return ciphertext, nil
}

// Decrypt decrypts the provided data with the key of the AES
// EncrypterDecrypter.
func (ed *AESEncrypterDecrypter) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ed.keyBytes)
	if err != nil {
		return nil, err
	}

	var plaintext []byte
	switch ed.mode {
	case GCM:
		gcm, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, err
		}

		plaintext, err = gcm.Open(nil, nil, data, nil)
		if err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}

// KeyID returns the key ID of the key used to create the AES EncrypterDecrypter
// instance.
func (ed *AESEncrypterDecrypter) KeyID() (string, error) {
	return ed.keyID, nil
}

func validateAESKeySize(key []byte) (int, error) {
	switch len(key) {
	// AES-128, AES-192, AES-256
	case 16, 24, 32:
		return len(key) / 8, nil
	default:
		return 0, ErrInvalidKeyLength
	}
}
