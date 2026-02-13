package symmetric

import (
	"fmt"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/encrypterdecrypter/symmetric/testdata"
	"github.com/stretchr/testify/assert"
)

func TestLoadSymmetricKey(t *testing.T) {
	tests := map[string]struct {
		keyBytes      []byte
		cipher        SSLibSymmetricCipher
		expectedKeyID string
	}{
		"AES key": {
			keyBytes:      testdata.AESKey,
			cipher:        AES,
			expectedKeyID: "3365676914098a99b563b1d5b90822916e78d1109640bbdaf196208db3edf908",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := LoadSymmetricKey(test.keyBytes, test.cipher)
			assert.Nil(t, err, fmt.Sprintf("unexpected error in test '%s'", name))
			assert.Equal(t, test.expectedKeyID, key.KeyID)
		})
	}
}
