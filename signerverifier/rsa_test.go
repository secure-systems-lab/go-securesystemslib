package signerverifier

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
)

func TestNewRSAPSSSignerVerifierFromSSLibKey(t *testing.T) {
	key, err := LoadRSAPSSKeyFromFile(filepath.Join("test-data", "rsa-test-key.pub"))
	if err != nil {
		t.Error(err)
	}

	sv, err := NewRSAPSSSignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Error(err)
	}

	expectedPublicString := "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA04egZRic+dZMVtiQc56D\nejU4FF1q3aOkUKnD+Q4lTbj1zp6ODKJTcktupmrad68jqtMiSGG8he6ELFs377q8\nbbgEUMWgAf+06Q8oFvUSfOXzZNFI7H5SMPOJY5aDWIMIEZ8DlcO7TfkA7D3iAEJX\nxxTOVS3UAIk5umO7Y7t7yXr8O/C4u78krGazCnoblcekMLJZV4O/5BloWNAe/B1c\nvZdaZUf3brD4ZZrxEtXw/tefhn1aHsSUajVW2wwjSpKhqj7Z0XS3bDS3T95/3xsN\n6+hlS6A7rJfiWpKIRHj0vh2SXLDmmhQl1In8TD/aiycTUyWcBRHVPlYFgYPt6SaT\nVQSgMzSxC43/2fINb2fyt8SbUHJ3Ct+mzRzd/1AQikWhBdstJLxInewzjYE/sb+c\n2CmCxMPQG2BwmAWXaaumeJcXVPBlMgAcjMatM8bPByTbXpKDnQslOE7g/gswDIwn\nEm53T13mZzYUvbLJ0q3aljZVLIC3IZn3ZwA2yCWchBkVAgMBAAE=\n-----END PUBLIC KEY-----"
	_, expectedPublicKey, err := decodeAndParsePEM([]byte(expectedPublicString))
	assert.Nil(t, err)

	assert.Equal(t, "4e8d20af09fcaed6c388a186427f94a5f7ff5591ec295f4aab2cff49ffe39e9b", sv.keyID)
	assert.Equal(t, expectedPublicKey.(*rsa.PublicKey), sv.public)
	assert.Nil(t, sv.private)
}

func TestLoadRSAPSSKeyFromFile(t *testing.T) {
	t.Run("RSA public key", func(t *testing.T) {
		key, err := LoadRSAPSSKeyFromFile(filepath.Join("test-data", "rsa-test-key.pub"))
		assert.Nil(t, err)

		assert.Equal(t, "4e8d20af09fcaed6c388a186427f94a5f7ff5591ec295f4aab2cff49ffe39e9b", key.KeyID)
		assert.Equal(t, "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA04egZRic+dZMVtiQc56D\nejU4FF1q3aOkUKnD+Q4lTbj1zp6ODKJTcktupmrad68jqtMiSGG8he6ELFs377q8\nbbgEUMWgAf+06Q8oFvUSfOXzZNFI7H5SMPOJY5aDWIMIEZ8DlcO7TfkA7D3iAEJX\nxxTOVS3UAIk5umO7Y7t7yXr8O/C4u78krGazCnoblcekMLJZV4O/5BloWNAe/B1c\nvZdaZUf3brD4ZZrxEtXw/tefhn1aHsSUajVW2wwjSpKhqj7Z0XS3bDS3T95/3xsN\n6+hlS6A7rJfiWpKIRHj0vh2SXLDmmhQl1In8TD/aiycTUyWcBRHVPlYFgYPt6SaT\nVQSgMzSxC43/2fINb2fyt8SbUHJ3Ct+mzRzd/1AQikWhBdstJLxInewzjYE/sb+c\n2CmCxMPQG2BwmAWXaaumeJcXVPBlMgAcjMatM8bPByTbXpKDnQslOE7g/gswDIwn\nEm53T13mZzYUvbLJ0q3aljZVLIC3IZn3ZwA2yCWchBkVAgMBAAE=\n-----END PUBLIC KEY-----", key.KeyVal.Public)
		assert.Equal(t, RSAKeyScheme, key.Scheme)
		assert.Equal(t, RSAKeyType, key.KeyType)
	})

	t.Run("RSA private key", func(t *testing.T) {
		key, err := LoadRSAPSSKeyFromFile(filepath.Join("test-data", "rsa-test-key"))
		assert.Nil(t, err)

		assert.Equal(t, "4e8d20af09fcaed6c388a186427f94a5f7ff5591ec295f4aab2cff49ffe39e9b", key.KeyID)
		assert.Equal(t, "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA04egZRic+dZMVtiQc56D\nejU4FF1q3aOkUKnD+Q4lTbj1zp6ODKJTcktupmrad68jqtMiSGG8he6ELFs377q8\nbbgEUMWgAf+06Q8oFvUSfOXzZNFI7H5SMPOJY5aDWIMIEZ8DlcO7TfkA7D3iAEJX\nxxTOVS3UAIk5umO7Y7t7yXr8O/C4u78krGazCnoblcekMLJZV4O/5BloWNAe/B1c\nvZdaZUf3brD4ZZrxEtXw/tefhn1aHsSUajVW2wwjSpKhqj7Z0XS3bDS3T95/3xsN\n6+hlS6A7rJfiWpKIRHj0vh2SXLDmmhQl1In8TD/aiycTUyWcBRHVPlYFgYPt6SaT\nVQSgMzSxC43/2fINb2fyt8SbUHJ3Ct+mzRzd/1AQikWhBdstJLxInewzjYE/sb+c\n2CmCxMPQG2BwmAWXaaumeJcXVPBlMgAcjMatM8bPByTbXpKDnQslOE7g/gswDIwn\nEm53T13mZzYUvbLJ0q3aljZVLIC3IZn3ZwA2yCWchBkVAgMBAAE=\n-----END PUBLIC KEY-----", key.KeyVal.Public)
		expectedPrivateKey := "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----" //nolint:gosec
		assert.Equal(t, expectedPrivateKey, key.KeyVal.Private)
		assert.Equal(t, RSAKeyScheme, key.Scheme)
		assert.Equal(t, RSAKeyType, key.KeyType)
	})

	t.Run("invalid path", func(t *testing.T) {
		_, err := LoadRSAPSSKeyFromFile(filepath.Join("test-data", "invalid"))
		assert.ErrorContains(t, err, "unable to load RSA key from file")
	})
}

func TestRSAPSSSignerVerifierSignAndVerify(t *testing.T) {
	t.Run("using valid key", func(t *testing.T) {
		key, err := LoadRSAPSSKeyFromFile(filepath.Join("test-data", "rsa-test-key"))
		if err != nil {
			t.Error(err)
		}

		sv, err := NewRSAPSSSignerVerifierFromSSLibKey(key)
		if err != nil {
			t.Error(err)
		}

		message := []byte("test message")

		signature, err := sv.Sign(context.Background(), message)
		assert.Nil(t, err)

		err = sv.Verify(context.Background(), message, signature)
		assert.Nil(t, err)
	})

	t.Run("using invalid key", func(t *testing.T) {
		key, err := LoadRSAPSSKeyFromFile(filepath.Join("test-data", "rsa-test-key.pub"))
		if err != nil {
			t.Error(err)
		}

		sv, err := NewRSAPSSSignerVerifierFromSSLibKey(key)
		if err != nil {
			t.Error(err)
		}

		message := []byte("test message")

		_, err = sv.Sign(context.Background(), message)
		assert.ErrorIs(t, err, ErrNotPrivateKey)
	})
}

func TestRSAPSSSignerVerifierWithDSSEEnvelope(t *testing.T) {
	key, err := LoadKey(rsaPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	sv, err := NewRSAPSSSignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Fatal(err)
	}

	payloadType := "application/vnd.dsse+json"
	payload := []byte("test message")

	es, err := dsse.NewEnvelopeSigner(sv)
	if err != nil {
		t.Error(err)
	}

	env, err := es.SignPayload(context.Background(), payloadType, payload)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "4e8d20af09fcaed6c388a186427f94a5f7ff5591ec295f4aab2cff49ffe39e9b", env.Signatures[0].KeyID)
	envPayload, err := env.DecodeB64Payload()
	assert.Equal(t, payload, envPayload)
	assert.Nil(t, err)

	key, err = LoadKey(rsaPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	sv, err = NewRSAPSSSignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Fatal(err)
	}

	ev, err := dsse.NewEnvelopeVerifier(sv)
	if err != nil {
		t.Error(err)
	}

	acceptedKeys, err := ev.Verify(context.Background(), env)
	assert.Nil(t, err)
	assert.Equal(t, "4e8d20af09fcaed6c388a186427f94a5f7ff5591ec295f4aab2cff49ffe39e9b", acceptedKeys[0].KeyID)
}

func TestRSAPSSSignerVerifierWithMetablockFile(t *testing.T) {
	key, err := LoadKey(rsaPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	sv, err := NewRSAPSSSignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Fatal(err)
	}

	metadataBytes, err := os.ReadFile(filepath.Join("test-data", "test-rsa.4e8d20af.link"))
	if err != nil {
		t.Fatal(err)
	}

	mb := struct {
		Signatures []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
		Signed any `json:"signed"`
	}{}

	if err := json.Unmarshal(metadataBytes, &mb); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "8958e5be66ee4352880a531bd097d1727adcc78e66b4faeb4a2cd6ad073dcb84f9a34e8156af39a7144cb5cd925325a18ccd4f0b2f981d6ff82655a7d63210d36655c50a0bf24e4839c10430a040dd6189d04fabec90eae4314c75ae2d585da17a56aaf6755e613a3a6a471ad2eddbb24504848e34f9ac163660f8ab80d7701bfa1189578a59597b3809ee62a70a7cc9545cfa65e23018fa442a45279b9fcf9d80bc92df711bfcfe16e3eae1bcf61b3286c1f0bdda17bc28bfab5b736bdcac4a38e31db1d0e0f56a2853b1b451650305f040a3425c3be47125700e92ef82c5a91a040b5e70ab7f6ebbe037ae1a6835044b5699748037e2e39a55a420c41cd9fa6e16868776367e3620e7d28eb9d8a3d710bdc98d488df1a9947d2ec8400f3c6209e8ca587cbffa30ceb3be98105e03182aab1bbb3c4e2560d99f0b09c012df2271f273ac70a6abb185abe11d559b118dca616417fa9205e74ab58e89ffd8b965da304ae9dc9cf6ffac4838b7c5375d6c2057a61cb286f06ad3b02a49c3af6178", mb.Signatures[0].Sig)
	assert.Equal(t, sv.keyID, mb.Signatures[0].KeyID)

	encodedBytes, err := cjson.EncodeCanonical(mb.Signed)
	if err != nil {
		t.Fatal(err)
	}

	decodedSig := hexDecode(t, mb.Signatures[0].Sig)

	err = sv.Verify(context.Background(), encodedBytes, decodedSig)
	assert.Nil(t, err)
}
