package signerverifier

import (
	"context"
	"crypto/rsa"
	"path/filepath"
	"testing"

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

	assert.Equal(t, "966c5d84ba73ccded42eb473c939d77336e4def253ffaf6739f8e983ef73dad8", sv.keyID) // FIXME: mismatch?
	assert.Equal(t, expectedPublicKey.(*rsa.PublicKey), sv.public)
	assert.Nil(t, sv.private)
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
	key, err := LoadRSAPSSKeyFromFile(filepath.Join("test-data", "rsa-test-key"))
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

	assert.Equal(t, "966c5d84ba73ccded42eb473c939d77336e4def253ffaf6739f8e983ef73dad8", env.Signatures[0].KeyID)
	envPayload, err := env.DecodeB64Payload()
	assert.Equal(t, payload, envPayload)
	assert.Nil(t, err)

	key, err = LoadRSAPSSKeyFromFile(filepath.Join("test-data", "rsa-test-key.pub"))
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
	assert.Equal(t, "966c5d84ba73ccded42eb473c939d77336e4def253ffaf6739f8e983ef73dad8", acceptedKeys[0].KeyID)
}
