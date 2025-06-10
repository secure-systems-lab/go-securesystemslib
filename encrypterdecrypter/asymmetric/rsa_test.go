package asymmetric

import (
	"crypto/rsa"
	"path/filepath"
	"testing"

	sv "github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	"github.com/stretchr/testify/assert"
)

var plaintext = []byte("reallyimportant")

func TestNewRSAEncrypterDecrypterFromSSLibKey(t *testing.T) {
	key, err := sv.LoadRSAPSSKeyFromFile(filepath.Join("..", "..", "signerverifier", "test-data", "rsa-test-key.pub"))
	if err != nil {
		t.Error(err)
	}

	ed, err := NewRSAEncrypterDecrypterFromSSLibKey(key)
	if err != nil {
		t.Error(err)
	}

	expectedPublicString := "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA04egZRic+dZMVtiQc56D\nejU4FF1q3aOkUKnD+Q4lTbj1zp6ODKJTcktupmrad68jqtMiSGG8he6ELFs377q8\nbbgEUMWgAf+06Q8oFvUSfOXzZNFI7H5SMPOJY5aDWIMIEZ8DlcO7TfkA7D3iAEJX\nxxTOVS3UAIk5umO7Y7t7yXr8O/C4u78krGazCnoblcekMLJZV4O/5BloWNAe/B1c\nvZdaZUf3brD4ZZrxEtXw/tefhn1aHsSUajVW2wwjSpKhqj7Z0XS3bDS3T95/3xsN\n6+hlS6A7rJfiWpKIRHj0vh2SXLDmmhQl1In8TD/aiycTUyWcBRHVPlYFgYPt6SaT\nVQSgMzSxC43/2fINb2fyt8SbUHJ3Ct+mzRzd/1AQikWhBdstJLxInewzjYE/sb+c\n2CmCxMPQG2BwmAWXaaumeJcXVPBlMgAcjMatM8bPByTbXpKDnQslOE7g/gswDIwn\nEm53T13mZzYUvbLJ0q3aljZVLIC3IZn3ZwA2yCWchBkVAgMBAAE=\n-----END PUBLIC KEY-----"
	_, expectedPublicKey, err := sv.DecodeAndParsePEM([]byte(expectedPublicString))
	assert.Nil(t, err)

	assert.Equal(t, "4e8d20af09fcaed6c388a186427f94a5f7ff5591ec295f4aab2cff49ffe39e9b", ed.keyID)
	assert.Equal(t, expectedPublicKey.(*rsa.PublicKey), ed.public)
	assert.Nil(t, ed.private)
}

func TestRoundtrip(t *testing.T) {
	key, err := sv.LoadRSAPSSKeyFromFile(filepath.Join("..", "..", "signerverifier", "test-data", "rsa-test-key"))
	if err != nil {
		t.Error(err)
	}

	ed, err := NewRSAEncrypterDecrypterFromSSLibKey(key)
	if err != nil {
		t.Error(err)
	}

	ciphertext, err := ed.Encrypt(plaintext)
	assert.Nil(t, err)

	decryptedPlaintext, err := ed.Decrypt(ciphertext)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, decryptedPlaintext)
}

func TestRoundtripCorrupted(t *testing.T) {
	key, err := sv.LoadRSAPSSKeyFromFile(filepath.Join("..", "..", "signerverifier", "test-data", "rsa-test-key"))
	if err != nil {
		t.Error(err)
	}

	ed, err := NewRSAEncrypterDecrypterFromSSLibKey(key)
	if err != nil {
		t.Error(err)
	}

	ciphertext, err := ed.Encrypt(plaintext)
	assert.Nil(t, err)

	ciphertext[0] = ^ciphertext[0]

	_, err = ed.Decrypt(ciphertext)
	assert.ErrorContains(t, err, "decryption error")
}
