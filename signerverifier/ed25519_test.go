package signerverifier

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
)

func TestNewED25519SignerVerifierFromSSLibKey(t *testing.T) {
	key, err := LoadED25519KeyFromFile(filepath.Join("test-data", "ed25519-test-key.pub"))
	if err != nil {
		t.Error(err)
	}

	sv, err := NewED25519SignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Error(err)
	}

	expectedPublicString := "3f586ce67329419fb0081bd995914e866a7205da463d593b3b490eab2b27fd3f"
	expectedPublicKey := ed25519.PublicKey(hexDecode(t, expectedPublicString))

	assert.Equal(t, "52e3b8e73279d6ebdd62a5016e2725ff284f569665eb92ccb145d83817a02997", sv.keyID)
	assert.Equal(t, expectedPublicKey, sv.public)
	assert.Nil(t, sv.private)
}

func TestLoadED25519KeyFromFile(t *testing.T) {
	t.Run("ED25519 public key", func(t *testing.T) {
		key, err := LoadED25519KeyFromFile(filepath.Join("test-data", "ed25519-test-key.pub"))
		assert.Nil(t, err)

		assert.Equal(t, "52e3b8e73279d6ebdd62a5016e2725ff284f569665eb92ccb145d83817a02997", key.KeyID)
		assert.Equal(t, "3f586ce67329419fb0081bd995914e866a7205da463d593b3b490eab2b27fd3f", key.KeyVal.Public)
		assert.Equal(t, "ed25519", key.Scheme)
		assert.Equal(t, ED25519KeyType, key.KeyType)
	})

	t.Run("ED25519 private key", func(t *testing.T) {
		key, err := LoadED25519KeyFromFile(filepath.Join("test-data", "ed25519-test-key"))
		assert.Nil(t, err)

		assert.Equal(t, "52e3b8e73279d6ebdd62a5016e2725ff284f569665eb92ccb145d83817a02997", key.KeyID)
		assert.Equal(t, "3f586ce67329419fb0081bd995914e866a7205da463d593b3b490eab2b27fd3f", key.KeyVal.Public)
		assert.Equal(t, "66f6ebad4aeb949b91c84c9cfd6ee351fc4fd544744bab6e30fb400ba13c6e9a", key.KeyVal.Private)
		assert.Equal(t, "ed25519", key.Scheme)
		assert.Equal(t, ED25519KeyType, key.KeyType)
	})

	t.Run("invalid path", func(t *testing.T) {
		_, err := LoadED25519KeyFromFile(filepath.Join("test-data", "invalid"))
		assert.ErrorContains(t, err, "unable to load ED25519 key from file")
	})
}

func TestED25519SignerVerifierSign(t *testing.T) {
	key, err := LoadED25519KeyFromFile(filepath.Join("test-data", "ed25519-test-key"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err := NewED25519SignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Error(err)
	}

	message := []byte("test message")

	signature, err := sv.Sign(context.Background(), message)
	if err != nil {
		t.Error(err)
	}

	expectedSignature := []byte{0x80, 0x72, 0xb4, 0x31, 0xc5, 0xa3, 0x7e, 0xc, 0xf3, 0x91, 0x22, 0x3, 0x60, 0xbf, 0x92, 0xa4, 0x46, 0x31, 0x84, 0x83, 0xf1, 0x31, 0x3, 0xdc, 0xbc, 0x5, 0x6f, 0xab, 0x84, 0xe4, 0xdc, 0xe9, 0xf5, 0x1c, 0xa9, 0xb3, 0x95, 0xa5, 0xa0, 0x16, 0xd3, 0xaa, 0x4d, 0xe7, 0xde, 0xaf, 0xc2, 0x5e, 0x1e, 0x9a, 0x9d, 0xc8, 0xb2, 0x5c, 0x1c, 0x68, 0xf7, 0x28, 0xb4, 0x1, 0x4d, 0x9f, 0xc8, 0x4}
	assert.Equal(t, expectedSignature, signature)

	key, err = LoadED25519KeyFromFile(filepath.Join("test-data", "ed25519-test-key.pub"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err = NewED25519SignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Error(err)
	}

	_, err = sv.Sign(context.Background(), message)
	assert.ErrorIs(t, err, ErrNotPrivateKey)
}

func TestED25519SignerVerifierVerify(t *testing.T) {
	key, err := LoadED25519KeyFromFile(filepath.Join("test-data", "ed25519-test-key.pub"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err := NewED25519SignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Error(err)
	}

	message := []byte("test message")
	signature := []byte{0x80, 0x72, 0xb4, 0x31, 0xc5, 0xa3, 0x7e, 0xc, 0xf3, 0x91, 0x22, 0x3, 0x60, 0xbf, 0x92, 0xa4, 0x46, 0x31, 0x84, 0x83, 0xf1, 0x31, 0x3, 0xdc, 0xbc, 0x5, 0x6f, 0xab, 0x84, 0xe4, 0xdc, 0xe9, 0xf5, 0x1c, 0xa9, 0xb3, 0x95, 0xa5, 0xa0, 0x16, 0xd3, 0xaa, 0x4d, 0xe7, 0xde, 0xaf, 0xc2, 0x5e, 0x1e, 0x9a, 0x9d, 0xc8, 0xb2, 0x5c, 0x1c, 0x68, 0xf7, 0x28, 0xb4, 0x1, 0x4d, 0x9f, 0xc8, 0x4}
	assert.Nil(t, sv.Verify(context.Background(), message, signature))

	message = []byte("corrupted message")
	err = sv.Verify(context.Background(), message, signature)
	assert.ErrorIs(t, err, ErrSignatureVerificationFailed)
}

func TestED25519SignerVerifierWithDSSEEnvelope(t *testing.T) {
	key, err := LoadED25519KeyFromFile(filepath.Join("test-data", "ed25519-test-key"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err := NewED25519SignerVerifierFromSSLibKey(key)
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

	assert.Equal(t, "52e3b8e73279d6ebdd62a5016e2725ff284f569665eb92ccb145d83817a02997", env.Signatures[0].KeyID)
	envPayload, err := env.DecodeB64Payload()
	assert.Equal(t, payload, envPayload)
	assert.Nil(t, err)

	key, err = LoadED25519KeyFromFile(filepath.Join("test-data", "ed25519-test-key.pub"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err = NewED25519SignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Fatal(err)
	}

	ev, err := dsse.NewEnvelopeVerifier(sv)
	if err != nil {
		t.Error(err)
	}

	acceptedKeys, err := ev.Verify(context.Background(), env)
	assert.Nil(t, err)
	assert.Equal(t, "52e3b8e73279d6ebdd62a5016e2725ff284f569665eb92ccb145d83817a02997", acceptedKeys[0].KeyID)
}

func TestED25519SignerVerifierWithMetablockFile(t *testing.T) {
	key, err := LoadED25519KeyFromFile(filepath.Join("test-data", "ed25519-test-key.pub"))
	if err != nil {
		t.Fatal(err)
	}

	sv, err := NewED25519SignerVerifierFromSSLibKey(key)
	if err != nil {
		t.Fatal(err)
	}

	metadataBytes, err := os.ReadFile(filepath.Join("test-data", "test-ed25519.52e3b8e7.link"))
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

	assert.Equal(t, "4c8b7605a9195d4ddba54493bbb5257a9836c1d16056a027fd77e97b95a4f3e36f8bc3c9c9960387d68187760b3072a30c44f992c5bf8f7497c303a3b0a32403", mb.Signatures[0].Sig)
	assert.Equal(t, sv.keyID, mb.Signatures[0].KeyID)

	encodedBytes, err := cjson.EncodeCanonical(mb.Signed)
	if err != nil {
		t.Fatal(err)
	}

	decodedSig := hexDecode(t, mb.Signatures[0].Sig)

	err = sv.Verify(context.Background(), encodedBytes, decodedSig)
	assert.Nil(t, err)
}
