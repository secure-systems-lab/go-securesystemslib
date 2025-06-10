package symmetric

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
)

func CalculateSymmetricKeyID(k *SSLibSymmetricKey) (string, error) {
	key := map[string]any{
		"cipher":  k.Cipher,
		"keysize": k.KeySize,
		"keyval":  k.KeyVal,
	}
	canonical, err := cjson.EncodeCanonical(key)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
