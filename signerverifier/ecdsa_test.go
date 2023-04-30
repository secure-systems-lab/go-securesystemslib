package signerverifier

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
)

func TestNewECDSASignerVerifierFromSSLibKey(t *testing.T) {
	key, err := LoadECDSAKeyFromFile(filepath.Join("test-data", "ecdsa-test-key.pub"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err := NewECDSASignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Fatal(err)
	}

	expectedPublicString := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu+HEqqpXLa48lXH9rkRygsfsCKq1\nXM36oXymJ9wxpM68nCqkrZCVnZ9lkEeCwD8qWYTNxD5yfWXwJjFh+K7qLQ==\n-----END PUBLIC KEY-----"
	_, expectedPublicKey, err := decodeAndParsePEM([]byte(expectedPublicString))
	assert.Nil(t, err)

	assert.Equal(t, "98adf38602c48c5479e9a991ee3f8cbf541ee4f985e00f7a5fc4148d9a45b704", sv.keyID)
	assert.Equal(t, expectedPublicKey, sv.public)
	assert.Nil(t, sv.private)
}

func TestECDSASignerVerifierSign(t *testing.T) {
	t.Run("using valid key", func(t *testing.T) {
		key, err := LoadECDSAKeyFromFile(filepath.Join("test-data", "ecdsa-test-key"))
		if err != nil {
			t.Fatal(err)
		}

		sv, err := NewECDSASignerVerifierFromSSLibKey(key)
		if err != nil {
			t.Fatal(err)
		}

		message := []byte("test message")

		signature, err := sv.Sign(context.Background(), message)
		assert.Nil(t, err)

		err = sv.Verify(context.Background(), message, signature)
		assert.Nil(t, err)
	})

	t.Run("using invalid key", func(t *testing.T) {
		key, err := LoadECDSAKeyFromFile(filepath.Join("test-data", "ecdsa-test-key.pub"))
		if err != nil {
			t.Fatal(err)
		}

		sv, err := NewECDSASignerVerifierFromSSLibKey(key)
		if err != nil {
			t.Fatal(err)
		}

		message := []byte("test message")

		_, err = sv.Sign(context.Background(), message)
		assert.ErrorIs(t, err, ErrNotPrivateKey)
	})
}

func TestECDSASignerVerifierWithDSSEEnvelope(t *testing.T) {
	key, err := LoadECDSAKeyFromFile(filepath.Join("test-data", "ecdsa-test-key"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err := NewECDSASignerVerifierFromSSLibKey(key)
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

	assert.Equal(t, "98adf38602c48c5479e9a991ee3f8cbf541ee4f985e00f7a5fc4148d9a45b704", env.Signatures[0].KeyID)
	envPayload, err := env.DecodeB64Payload()
	assert.Equal(t, payload, envPayload)
	assert.Nil(t, err)

	key, err = LoadECDSAKeyFromFile(filepath.Join("test-data", "ecdsa-test-key.pub"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err = NewECDSASignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Fatal(err)
	}

	ev, err := dsse.NewEnvelopeVerifier(sv)
	if err != nil {
		t.Error(err)
	}

	acceptedKeys, err := ev.Verify(context.Background(), env)
	assert.Nil(t, err)
	assert.Equal(t, "98adf38602c48c5479e9a991ee3f8cbf541ee4f985e00f7a5fc4148d9a45b704", acceptedKeys[0].KeyID)
}
