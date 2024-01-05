package signerverifier

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed test-data/rsa-test-key
var rsaPrivateKey []byte

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
	expectedRSAPrivateKey := "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----"
	expectedRSAPublicKey := "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA04egZRic+dZMVtiQc56D\nejU4FF1q3aOkUKnD+Q4lTbj1zp6ODKJTcktupmrad68jqtMiSGG8he6ELFs377q8\nbbgEUMWgAf+06Q8oFvUSfOXzZNFI7H5SMPOJY5aDWIMIEZ8DlcO7TfkA7D3iAEJX\nxxTOVS3UAIk5umO7Y7t7yXr8O/C4u78krGazCnoblcekMLJZV4O/5BloWNAe/B1c\nvZdaZUf3brD4ZZrxEtXw/tefhn1aHsSUajVW2wwjSpKhqj7Z0XS3bDS3T95/3xsN\n6+hlS6A7rJfiWpKIRHj0vh2SXLDmmhQl1In8TD/aiycTUyWcBRHVPlYFgYPt6SaT\nVQSgMzSxC43/2fINb2fyt8SbUHJ3Ct+mzRzd/1AQikWhBdstJLxInewzjYE/sb+c\n2CmCxMPQG2BwmAWXaaumeJcXVPBlMgAcjMatM8bPByTbXpKDnQslOE7g/gswDIwn\nEm53T13mZzYUvbLJ0q3aljZVLIC3IZn3ZwA2yCWchBkVAgMBAAE=\n-----END PUBLIC KEY-----"
	expectedRSAKeyID := "4e8d20af09fcaed6c388a186427f94a5f7ff5591ec295f4aab2cff49ffe39e9b"

	// ED25519 expected values
	expectedED25519PrivateKey := "66f6ebad4aeb949b91c84c9cfd6ee351fc4fd544744bab6e30fb400ba13c6e9a3f586ce67329419fb0081bd995914e866a7205da463d593b3b490eab2b27fd3f"
	expectedED25519PublicKey := "3f586ce67329419fb0081bd995914e866a7205da463d593b3b490eab2b27fd3f"
	expectedED25519KeyID := "52e3b8e73279d6ebdd62a5016e2725ff284f569665eb92ccb145d83817a02997"

	// ECDSA expected values
	expectedECDSAPrivateKey := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCjoPFeWCpjL5OS+h\nwg7JaWoDcpW2np2VJjuVLeSR4QyhRANCAAS74cSqqlctrjyVcf2uRHKCx+wIqrVc\nzfqhfKYn3DGkzrycKqStkJWdn2WQR4LAPypZhM3EPnJ9ZfAmMWH4ruot\n-----END PRIVATE KEY-----"
	expectedECDSAPublicKey := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu+HEqqpXLa48lXH9rkRygsfsCKq1\nXM36oXymJ9wxpM68nCqkrZCVnZ9lkEeCwD8qWYTNxD5yfWXwJjFh+K7qLQ==\n-----END PUBLIC KEY-----"
	expectedECDSAKeyID := "98adf38602c48c5479e9a991ee3f8cbf541ee4f985e00f7a5fc4148d9a45b704"

	t.Run("RSA private key", func(t *testing.T) {
		key, err := LoadKey(rsaPrivateKey)
		assert.Nil(t, err)
		assert.Equal(t, expectedRSAKeyID, key.KeyID)
		assert.Equal(t, expectedRSAPublicKey, key.KeyVal.Public)
		assert.Equal(t, expectedRSAPrivateKey, key.KeyVal.Private)
		assert.Equal(t, RSAKeyScheme, key.Scheme)
		assert.Equal(t, RSAKeyType, key.KeyType)
	})

	t.Run("RSA public key", func(t *testing.T) {
		key, err := LoadKey(rsaPublicKey)
		assert.Nil(t, err)
		assert.Equal(t, expectedRSAKeyID, key.KeyID)
		assert.Equal(t, expectedRSAPublicKey, key.KeyVal.Public)
		assert.Equal(t, "", key.KeyVal.Private)
		assert.Equal(t, RSAKeyScheme, key.Scheme)
		assert.Equal(t, RSAKeyType, key.KeyType)
	})

	t.Run("ED25519 private key", func(t *testing.T) {
		key, err := LoadKey(ed25519PrivateKey)
		assert.Nil(t, err)
		assert.Equal(t, expectedED25519KeyID, key.KeyID)
		assert.Equal(t, expectedED25519PublicKey, key.KeyVal.Public)
		assert.Equal(t, expectedED25519PrivateKey, key.KeyVal.Private)
		assert.Equal(t, ED25519KeyType, key.Scheme)
		assert.Equal(t, ED25519KeyType, key.KeyType)
	})

	t.Run("ED25519 public key", func(t *testing.T) {
		key, err := LoadKey(ed25519PublicKey)
		assert.Nil(t, err)
		assert.Equal(t, expectedED25519KeyID, key.KeyID)
		assert.Equal(t, expectedED25519PublicKey, key.KeyVal.Public)
		assert.Equal(t, "", key.KeyVal.Private)
		assert.Equal(t, ED25519KeyType, key.Scheme)
		assert.Equal(t, ED25519KeyType, key.KeyType)
	})

	t.Run("ECDSA private key", func(t *testing.T) {
		key, err := LoadKey(ecdsaPrivateKey)
		assert.Nil(t, err)
		assert.Equal(t, expectedECDSAKeyID, key.KeyID)
		assert.Equal(t, expectedECDSAPublicKey, key.KeyVal.Public)
		assert.Equal(t, expectedECDSAPrivateKey, key.KeyVal.Private)
		assert.Equal(t, ECDSAKeyScheme, key.Scheme)
		assert.Equal(t, ECDSAKeyType, key.KeyType)
	})

	t.Run("ECDSA public key", func(t *testing.T) {
		key, err := LoadKey(ecdsaPublicKey)
		assert.Nil(t, err)
		assert.Equal(t, expectedECDSAKeyID, key.KeyID)
		assert.Equal(t, expectedECDSAPublicKey, key.KeyVal.Public)
		assert.Equal(t, "", key.KeyVal.Private)
		assert.Equal(t, ECDSAKeyScheme, key.Scheme)
		assert.Equal(t, ECDSAKeyType, key.KeyType)
	})
}
