package dsse

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvelopeVerifier_Verify_HandlesNil(t *testing.T) {
	verifier, err := NewEnvelopeVerifier(&mockVerifier{})
	assert.NoError(t, err)

	acceptedKeys, err := verifier.Verify(context.TODO(), nil)
	assert.Empty(t, acceptedKeys)
	assert.EqualError(t, err, "cannot verify a nil envelope")
}

type mockVerifier struct {
	returnErr error
}

func (m *mockVerifier) Verify(_ context.Context, _, _ []byte) error {
	if m.returnErr != nil {
		return m.returnErr
	}
	return nil
}

func (m *mockVerifier) KeyID() (string, error) {
	return "mock", errors.New("Unsupported keyid")
}

func (m *mockVerifier) Public() crypto.PublicKey {
	return "mock-public"
}

// Test against the example in the protocol specification:
// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
func TestVerify(t *testing.T) {
	var keyID = "test key 123"
	var payloadType = "http://example.com/HelloWorld"

	e := Envelope{
		Payload:     "aGVsbG8gd29ybGQ=",
		PayloadType: payloadType,
		Signatures: []Signature{
			{
				KeyID: keyID,
				Sig:   "Cc3RkvYsLhlaFVd+d6FPx4ZClhqW4ZT0rnCYAfv6/ckoGdwT7g/blWNpOBuL/tZhRiVFaglOGTU8GEjm4aEaNA==",
			},
		},
	}

	ev, err := NewEnvelopeVerifier(&mockVerifier{})
	assert.Nil(t, err, "unexpected error")
	acceptedKeys, err := ev.Verify(context.TODO(), &e)

	// Now verify
	assert.Nil(t, err, "unexpected error")
	assert.Len(t, acceptedKeys, 1, "unexpected keys")
	assert.Equal(t, acceptedKeys[0].KeyID, "", "unexpected keyid")

	// Now try an error
	ev, err = NewEnvelopeVerifier(&mockVerifier{returnErr: errors.New("uh oh")})
	assert.Nil(t, err, "unexpected error")
	_, err = ev.Verify(context.TODO(), &e)

	// Now verify
	assert.Error(t, err)
}

func TestVerifyOneProvider(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var ns nilSignerVerifier
	signer, err := NewEnvelopeSigner(ns)
	assert.Nil(t, err, "unexpected error")

	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewEnvelopeVerifier(ns)
	assert.Nil(t, err, "unexpected error")
	acceptedKeys, err := verifier.Verify(context.TODO(), env)
	assert.Nil(t, err, "unexpected error")
	assert.Len(t, acceptedKeys, 1, "unexpected keys")
	assert.Equal(t, acceptedKeys[0].KeyID, "nil", "unexpected keyid")
}

func TestVerifyMultipleProvider(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var ns nilSignerVerifier
	var null nullSignerVerifier
	signer, err := NewEnvelopeSigner(ns, null)
	assert.Nil(t, err, "unexpected error")

	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewEnvelopeVerifier(ns, null)
	assert.Nil(t, err, "unexpected error")
	acceptedKeys, err := verifier.Verify(context.TODO(), env)
	assert.Nil(t, err, "unexpected error")
	assert.Len(t, acceptedKeys, 2, "unexpected keys")
}

func TestVerifyMultipleProviderThreshold(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var ns nilSignerVerifier
	var null nullSignerVerifier
	signer, err := NewEnvelopeSigner(ns, null)
	assert.Nil(t, err)
	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewMultiEnvelopeVerifier(2, ns, null)
	assert.Nil(t, err, "unexpected error")
	acceptedKeys, err := verifier.Verify(context.TODO(), env)
	assert.Nil(t, err, "unexpected error")
	assert.Len(t, acceptedKeys, 2, "unexpected keys")
}

func TestVerifyMultipleProviderThresholdErr(t *testing.T) {
	var ns nilSignerVerifier
	var null nullSignerVerifier
	_, err := NewMultiEnvelopeVerifier(3, ns, null)
	assert.Equal(t, errThreshold, err, "wrong error")
	_, err = NewMultiEnvelopeVerifier(0, ns, null)
	assert.Equal(t, errThreshold, err, "wrong error")
}

func TestVerifyErr(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var errsv errSignerVerifier
	signer, err := NewEnvelopeSigner(errsv)
	assert.Nil(t, err, "unexpected error")

	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewEnvelopeVerifier(errsv)
	assert.Nil(t, err, "unexpected error")
	_, err = verifier.Verify(context.TODO(), env)
	assert.Equal(t, errVerify, err, "wrong error")
}

func TestBadVerifier(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var badv badverifier
	signer, err := NewEnvelopeSigner(badv)
	assert.Nil(t, err, "unexpected error")

	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewEnvelopeVerifier(badv)
	assert.Nil(t, err, "unexpected error")
	_, err = verifier.Verify(context.TODO(), env)
	assert.NotNil(t, err, "expected error")
}

func TestVerifyNoSig(t *testing.T) {
	var badv badverifier
	verifier, err := NewEnvelopeVerifier(badv)
	assert.Nil(t, err, "unexpected error")

	env := &Envelope{}

	_, err = verifier.Verify(context.TODO(), env)
	assert.Equal(t, ErrNoSignature, err, "wrong error")
}

func TestVerifyBadBase64(t *testing.T) {
	var badv badverifier
	verifier, err := NewEnvelopeVerifier(badv)
	assert.Nil(t, err, "unexpected error")

	expectedErr := fmt.Errorf("unable to base64 decode payload (is payload in the right format?)")

	t.Run("Payload", func(t *testing.T) {
		env := &Envelope{
			Payload: "Not base 64",
			Signatures: []Signature{
				{},
			},
		}

		_, err := verifier.Verify(context.TODO(), env)
		assert.IsType(t, expectedErr, err, "wrong error")
	})

	t.Run("Signature", func(t *testing.T) {
		env := &Envelope{
			Payload: "cGF5bG9hZAo=",
			Signatures: []Signature{
				{
					Sig: "not base 64",
				},
			},
		}

		_, err := verifier.Verify(context.TODO(), env)
		assert.IsType(t, expectedErr, err, "wrong error")
	})
}

func TestVerifyNoMatch(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"

	var ns nilSignerVerifier
	var null nullSignerVerifier
	verifier, err := NewEnvelopeVerifier(ns, null)
	assert.Nil(t, err, "unexpected error")

	env := &Envelope{
		PayloadType: payloadType,
		Payload:     "cGF5bG9hZAo=",
		Signatures: []Signature{
			{
				KeyID: "not found",
				Sig:   "cGF5bG9hZAo=",
			},
		},
	}

	_, err = verifier.Verify(context.TODO(), env)
	assert.NotNil(t, err, "expected error")
}

type interceptSignerVerifier struct {
	keyID        string
	verifyRes    bool
	verifyCalled bool
}

func (i *interceptSignerVerifier) Sign(_ context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (i *interceptSignerVerifier) Verify(_ context.Context, _, _ []byte) error {
	i.verifyCalled = true

	if i.verifyRes {
		return nil
	}
	return errVerify
}

func (i *interceptSignerVerifier) KeyID() (string, error) {
	return i.keyID, nil
}

func (i *interceptSignerVerifier) Public() crypto.PublicKey {
	return "intercept-public"
}

func TestVerifyOneFail(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var s1 = &interceptSignerVerifier{
		keyID:     "i1",
		verifyRes: true,
	}
	var s2 = &interceptSignerVerifier{
		keyID:     "i2",
		verifyRes: false,
	}
	signer, err := NewEnvelopeSigner(s1, s2)
	assert.Nil(t, err, "unexpected error")

	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewEnvelopeVerifier(s1, s2)
	assert.Nil(t, err, "unexpected error")
	acceptedKeys, err := verifier.Verify(context.TODO(), env)
	assert.Nil(t, err, "expected error")
	assert.True(t, s1.verifyCalled, "verify not called")
	assert.True(t, s2.verifyCalled, "verify not called")
	assert.Len(t, acceptedKeys, 1, "unexpected keys")
	assert.Equal(t, acceptedKeys[0].KeyID, "i1", "unexpected keyid")
}

func TestVerifySameKeyID(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var s1 = &interceptSignerVerifier{
		keyID:     "i1",
		verifyRes: true,
	}
	var s2 = &interceptSignerVerifier{
		keyID:     "i1",
		verifyRes: true,
	}
	signer, err := NewEnvelopeSigner(s1, s2)
	assert.Nil(t, err, "unexpected error")

	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewEnvelopeVerifier(s1, s2)
	assert.Nil(t, err, "unexpected error")
	acceptedKeys, err := verifier.Verify(context.TODO(), env)
	assert.Nil(t, err, "expected error")
	assert.True(t, s1.verifyCalled, "verify not called")
	assert.True(t, s2.verifyCalled, "verify not called")
	assert.Len(t, acceptedKeys, 1, "unexpected keys")
	assert.Equal(t, acceptedKeys[0].KeyID, "i1", "unexpected keyid")
}

func TestVerifyEmptyKeyID(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var s1 = &interceptSignerVerifier{
		keyID:     "",
		verifyRes: true,
	}

	var s2 = &interceptSignerVerifier{
		keyID:     "",
		verifyRes: true,
	}

	signer, err := NewEnvelopeSigner(s1, s2)
	assert.Nil(t, err, "unexpected error")

	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewEnvelopeVerifier(s1, s2)
	assert.Nil(t, err, "unexpected error")
	acceptedKeys, err := verifier.Verify(context.TODO(), env)
	assert.Nil(t, err, "expected error")
	assert.Len(t, acceptedKeys, 1, "unexpected keys")
	assert.Equal(t, acceptedKeys[0].KeyID, "", "unexpected keyid")
}

func TestVerifyPublicKeyID(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"
	var keyID = "SHA256:f4AuBLdH4Lj/dIuwAUXXebzoI9B/cJ4iSQ3/qByIl4M"

	var s1 = &ecdsaSignerVerifier{
		keyID: "",
		key:   newEcdsaKey(),
	}

	var s2 = &ecdsaSignerVerifier{
		keyID: "",
		key:   newEcdsaKey(),
	}

	signer, err := NewEnvelopeSigner(s1, s2)
	assert.Nil(t, err, "unexpected error")

	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewEnvelopeVerifier(s1, s2)
	assert.Nil(t, err, "unexpected error")
	acceptedKeys, err := verifier.Verify(context.TODO(), env)
	assert.Nil(t, err, "expected error")
	assert.Len(t, acceptedKeys, 1, "unexpected keys")
	assert.Equal(t, acceptedKeys[0].KeyID, keyID, "unexpected keyid")
}

func TestVerifyMultipleProviderAndEnvelopes(t *testing.T) {
	const payloadType = "http://example.com/HelloWorld"
	const payload = "hello world"

	var ns nilSignerVerifier
	var null nullSignerVerifier

	signerNil, err := NewEnvelopeSigner(ns)
	assert.Nil(t, err, "unexpected error")

	signerNull, err := NewEnvelopeSigner(null)
	assert.Nil(t, err, "unexpected error")

	envNil1, err := signerNil.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	envNil2, err := signerNil.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	envNull, err := signerNull.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")

	verifier, err := NewEnvelopeVerifier(ns, null)
	assert.Nil(t, err, "unexpected error")

	acceptedKeysNil1, err := verifier.Verify(context.TODO(), envNil1)
	assert.Nil(t, err, "unexpected error")
	assert.Len(t, acceptedKeysNil1, 1, "unexpected keys")
	assert.Equal(t, "nil", acceptedKeysNil1[0].KeyID, "unexpected keyid")

	acceptedKeysNil2, err := verifier.Verify(context.TODO(), envNil2)
	assert.Nil(t, err, "unexpected error")
	assert.Len(t, acceptedKeysNil2, 1, "unexpected keys")
	assert.Equal(t, "nil", acceptedKeysNil2[0].KeyID, "unexpected keyid")

	acceptedKeysNull, err := verifier.Verify(context.TODO(), envNull)
	assert.Nil(t, err, "unexpected error")
	assert.Len(t, acceptedKeysNull, 1, "unexpected keys")
	assert.Equal(t, "null", acceptedKeysNull[0].KeyID, "unexpected keyid")
}
