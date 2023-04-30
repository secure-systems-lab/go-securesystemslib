package signerverifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
)

var (
	ErrNotPrivateKey               = errors.New("loaded key is not a private key")
	ErrSignatureVerificationFailed = errors.New("failed to verify signature")
	ErrUnknownKeyType              = errors.New("unknown key type")
	ErrInvalidThreshold            = errors.New("threshold is either less than 1 or greater than number of provided public keys")
)

type SSLibKey struct {
	KeyIDHashAlgorithms []string `json:"keyid_hash_algorithms"`
	KeyType             string   `json:"keytype"`
	KeyVal              KeyVal   `json:"keyval"`
	Scheme              string   `json:"scheme"`
	keyID               string
}

func (k *SSLibKey) KeyID() string {
	return k.keyID
}

type KeyVal struct {
	Private     string `json:"private,omitempty"`
	Public      string `json:"public"`
	Certificate string `json:"certificate,omitempty"`
}

// LoadKeyFromBytes returns a pointer to a Key instance created from the
// contents of the bytes. The key contents are expected to be in the custom
// securesystemslib format.
func LoadKeyFromBytes(contents []byte) (*SSLibKey, error) {
	var key *SSLibKey
	if err := json.Unmarshal(contents, &key); err != nil {
		return nil, err
	}

	keyID, err := calculateKeyID(key)
	if err != nil {
		return nil, err
	}
	key.keyID = keyID

	return key, nil
}

func LoadKeyFromFile(path string) (*SSLibKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return LoadKeyFromBytes(contents)
}

func calculateKeyID(k *SSLibKey) (string, error) {
	canonical, err := cjson.EncodeCanonical(k)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
