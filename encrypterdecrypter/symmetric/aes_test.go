package symmetric

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/encrypterdecrypter/symmetric/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var plaintext = []byte("reallyimportant")

func TestRoundtrip(t *testing.T) {
	key, err := hex.DecodeString(string(testdata.AESKey))
	require.Nil(t, err)

	fmt.Println(key)

	ed := &AESEncrypterDecrypter{
		keyID:    "super secret key",
		keyBytes: key,
		mode:     GCM,
	}

	ciphertext, err := ed.Encrypt(plaintext)
	assert.Nil(t, err)

	decryptedPlaintext, err := ed.Decrypt(ciphertext)
	assert.Nil(t, err)

	assert.Equal(t, plaintext, decryptedPlaintext)
}

func TestRoundtripCorrupted(t *testing.T) {
	key, err := hex.DecodeString(string(testdata.AESKey))
	require.Nil(t, err)

	ed := &AESEncrypterDecrypter{
		keyID:    "super secret key",
		keyBytes: key,
		mode:     GCM,
	}

	ciphertext, err := ed.Encrypt(plaintext)
	assert.Nil(t, err)

	ciphertext[0] = ^ciphertext[0]

	_, err = ed.Decrypt(ciphertext)
	assert.ErrorContains(t, err, "message authentication failed")
}
