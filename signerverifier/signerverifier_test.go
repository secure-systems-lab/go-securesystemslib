package signerverifier

import (
	_ "embed"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed test-data/rsa-test-key
var rsaPrivateKey []byte

//go:embed test-data/rsa-test-key-pkcs8
var rsaPrivateKeyPKCS8 []byte

//go:embed test-data/rsa-test-key.pub
var rsaPublicKey []byte

//go:embed test-data/ed25519-test-key-pem
var ed25519PrivateKey []byte

//go:embed test-data/ed25519-test-key-pem.pub
var ed25519PublicKey []byte

//go:embed test-data/ecdsa-test-key-pem
var ecdsaPrivateKey []byte

//go:embed test-data/ecdsa-test-key-pem.pub
var ecdsaPublicKey []byte

func TestLoadKey(t *testing.T) {
	// RSA expected values
	expectedRSAPrivateKey := strings.TrimSpace(strings.ReplaceAll(string(rsaPrivateKey), "\r\n", "\n"))
	expectedRSAPrivateKeyPKCS8 := strings.TrimSpace(strings.ReplaceAll(string(rsaPrivateKeyPKCS8), "\r\n", "\n"))
	expectedRSAPublicKey := strings.TrimSpace(strings.ReplaceAll(string(rsaPublicKey), "\r\n", "\n"))
	expectedRSAKeyID := "4e8d20af09fcaed6c388a186427f94a5f7ff5591ec295f4aab2cff49ffe39e9b"

	// ED25519 expected values
	expectedED25519PrivateKey := "66f6ebad4aeb949b91c84c9cfd6ee351fc4fd544744bab6e30fb400ba13c6e9a3f586ce67329419fb0081bd995914e866a7205da463d593b3b490eab2b27fd3f"
	expectedED25519PublicKey := "3f586ce67329419fb0081bd995914e866a7205da463d593b3b490eab2b27fd3f"
	expectedED25519KeyID := "52e3b8e73279d6ebdd62a5016e2725ff284f569665eb92ccb145d83817a02997"

	// ECDSA expected values
	expectedECDSAPrivateKey := strings.TrimSpace(strings.ReplaceAll(string(ecdsaPrivateKey), "\r\n", "\n"))
	expectedECDSAPublicKey := strings.TrimSpace(strings.ReplaceAll(string(ecdsaPublicKey), "\r\n", "\n"))
	expectedECDSAKeyID := "98adf38602c48c5479e9a991ee3f8cbf541ee4f985e00f7a5fc4148d9a45b704"

	tests := map[string]struct {
		keyBytes           []byte
		expectedPrivateKey string
		expectedPublicKey  string
		expectedKeyID      string
		expectedKeyType    string
		expectedScheme     string
	}{
		"RSA private key": {
			keyBytes:           rsaPrivateKey,
			expectedPrivateKey: expectedRSAPrivateKey,
			expectedPublicKey:  expectedRSAPublicKey,
			expectedKeyID:      expectedRSAKeyID,
			expectedKeyType:    RSAKeyType,
			expectedScheme:     RSAKeyScheme,
		},
		"RSA private key (PKCS8)": {
			keyBytes:           rsaPrivateKeyPKCS8,
			expectedPrivateKey: expectedRSAPrivateKeyPKCS8,
			expectedPublicKey:  expectedRSAPublicKey,
			expectedKeyID:      expectedRSAKeyID,
			expectedKeyType:    RSAKeyType,
			expectedScheme:     RSAKeyScheme,
		},
		"RSA public key": {
			keyBytes:           rsaPublicKey,
			expectedPrivateKey: "",
			expectedPublicKey:  expectedRSAPublicKey,
			expectedKeyID:      expectedRSAKeyID,
			expectedKeyType:    RSAKeyType,
			expectedScheme:     RSAKeyScheme,
		},
		"ED25519 private key": {
			keyBytes:           ed25519PrivateKey,
			expectedPrivateKey: expectedED25519PrivateKey,
			expectedPublicKey:  expectedED25519PublicKey,
			expectedKeyID:      expectedED25519KeyID,
			expectedKeyType:    ED25519KeyType,
			expectedScheme:     ED25519KeyType,
		},
		"ED25519 public key": {
			keyBytes:           ed25519PublicKey,
			expectedPrivateKey: "",
			expectedPublicKey:  expectedED25519PublicKey,
			expectedKeyID:      expectedED25519KeyID,
			expectedKeyType:    ED25519KeyType,
			expectedScheme:     ED25519KeyType,
		},
		"ECDSA private key": {
			keyBytes:           ecdsaPrivateKey,
			expectedPrivateKey: expectedECDSAPrivateKey,
			expectedPublicKey:  expectedECDSAPublicKey,
			expectedKeyID:      expectedECDSAKeyID,
			expectedKeyType:    ECDSAKeyType,
			expectedScheme:     ECDSAKeyScheme,
		},
		"ECDSA public key": {
			keyBytes:           ecdsaPublicKey,
			expectedPrivateKey: "",
			expectedPublicKey:  expectedECDSAPublicKey,
			expectedKeyID:      expectedECDSAKeyID,
			expectedKeyType:    ECDSAKeyType,
			expectedScheme:     ECDSAKeyScheme,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := LoadKey(test.keyBytes)
			assert.Nil(t, err, fmt.Sprintf("unexpected error in test '%s'", name))
			assert.Equal(t, test.expectedKeyID, key.KeyID)
			assert.Equal(t, test.expectedPublicKey, key.KeyVal.Public)
			assert.Equal(t, test.expectedPrivateKey, key.KeyVal.Private)
			assert.Equal(t, test.expectedScheme, key.Scheme)
			assert.Equal(t, test.expectedKeyType, key.KeyType)
		})
	}
}
