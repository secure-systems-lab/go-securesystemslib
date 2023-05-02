package signerverifier

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
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

func TestLoadECDSAKeyFromFile(t *testing.T) {
	t.Run("ecdsa public key", func(t *testing.T) {
		key, err := LoadECDSAKeyFromFile(filepath.Join("test-data", "ecdsa-test-key.pub"))
		assert.Nil(t, err)

		assert.Equal(t, "98adf38602c48c5479e9a991ee3f8cbf541ee4f985e00f7a5fc4148d9a45b704", key.KeyID)
		assert.Equal(t, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu+HEqqpXLa48lXH9rkRygsfsCKq1\nXM36oXymJ9wxpM68nCqkrZCVnZ9lkEeCwD8qWYTNxD5yfWXwJjFh+K7qLQ==\n-----END PUBLIC KEY-----", key.KeyVal.Public)
		assert.Equal(t, "ecdsa-sha2-nistp256", key.Scheme)
		assert.Equal(t, ECDSAKeyType, key.KeyType)
	})

	t.Run("ecdsa private key", func(t *testing.T) {
		key, err := LoadECDSAKeyFromFile(filepath.Join("test-data", "ecdsa-test-key"))
		assert.Nil(t, err)

		assert.Equal(t, "98adf38602c48c5479e9a991ee3f8cbf541ee4f985e00f7a5fc4148d9a45b704", key.KeyID)
		assert.Equal(t, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu+HEqqpXLa48lXH9rkRygsfsCKq1\nXM36oXymJ9wxpM68nCqkrZCVnZ9lkEeCwD8qWYTNxD5yfWXwJjFh+K7qLQ==\n-----END PUBLIC KEY-----", key.KeyVal.Public)
		assert.Equal(t, "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIAo6DxXlgqYy+TkvocIOyWlqA3KVtp6dlSY7lS3kkeEMoAoGCCqGSM49\nAwEHoUQDQgAEu+HEqqpXLa48lXH9rkRygsfsCKq1XM36oXymJ9wxpM68nCqkrZCV\nnZ9lkEeCwD8qWYTNxD5yfWXwJjFh+K7qLQ==\n-----END EC PRIVATE KEY-----", key.KeyVal.Private)
		assert.Equal(t, "ecdsa-sha2-nistp256", key.Scheme)
		assert.Equal(t, ECDSAKeyType, key.KeyType)
	})

	t.Run("invalid path", func(t *testing.T) {
		_, err := LoadECDSAKeyFromFile(filepath.Join("test-data", "invalid"))
		assert.ErrorContains(t, err, "unable to load ECDSA key from file")
	})
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

func TestECDSASignerVerifierWithMetablockFile(t *testing.T) {
	key, err := LoadECDSAKeyFromFile(filepath.Join("test-data", "ecdsa-test-key.pub"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err := NewECDSASignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Fatal(err)
	}

	metadataBytes, err := os.ReadFile(filepath.Join("test-data", "test-ecdsa.98adf386.link"))
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

	assert.Equal(t, "304502201fbb03c0937504182a48c66f9218bdcb2e99a07ada273e92e5e543867f98c8d7022100dbfa7bbf74fd76d76c1d08676419cba85bbd81dfb000f3ac6a786693ddc508f5", mb.Signatures[0].Sig)
	assert.Equal(t, sv.keyID, mb.Signatures[0].KeyID)

	encodedBytes, err := cjson.EncodeCanonical(mb.Signed)
	if err != nil {
		t.Fatal(err)
	}

	decodedSig := hexDecode(t, mb.Signatures[0].Sig)

	err = sv.Verify(context.Background(), encodedBytes, decodedSig)
	assert.Nil(t, err)
}
