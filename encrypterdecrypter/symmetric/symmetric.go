package symmetric

import (
	"encoding/hex"
	"errors"
)

var ErrUnknownKeyType = errors.New("unknown key type")

type SSLibSymmetricCipher uint8

const (
	AES SSLibSymmetricCipher = iota
)

type SSLibSymmetricKey struct {
	KeyID   string               `json:"keyid"`
	Cipher  SSLibSymmetricCipher `json:"scheme"`
	KeySize int                  `json:"keysize"`
	KeyVal  []byte               `json:"keyval"`
}

// LoadSymmetricKey returns an SSLibSymmetricKey object when provided a byte
// array and cipher. Currently, AES-128/192/256 are supported.
func LoadSymmetricKey(keyBytes []byte, cipher SSLibSymmetricCipher) (*SSLibSymmetricKey, error) {
	var key *SSLibSymmetricKey

	switch cipher {
	case AES:
		keyBytes, err := hex.DecodeString(string(keyBytes))
		if err != nil {
			return nil, err
		}

		keySize, err := validateAESKeySize(keyBytes)
		if err != nil {
			return nil, err
		}

		key = &SSLibSymmetricKey{
			KeyID:   "",
			Cipher:  cipher,
			KeySize: keySize,
			KeyVal:  keyBytes,
		}
	default:
		return nil, ErrUnknownKeyType
	}

	keyID, err := CalculateSymmetricKeyID(key)
	if err != nil {
		return nil, err
	}
	key.KeyID = keyID
	return key, nil
}
