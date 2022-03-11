package dsse

import (
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvelopeVerifier_Verify_HandlesNil(t *testing.T) {
	verifier, err := NewEnvelopeVerifier(&mockVerifier{})
	assert.NoError(t, err)

	acceptedKeys, err := verifier.Verify(nil)
	assert.Empty(t, acceptedKeys)
	assert.EqualError(t, err, "cannot verify a nil envelope")
}

type mockVerifier struct {
	returnErr error
}

func (m *mockVerifier) Verify(data, sig []byte) error {
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
	acceptedKeys, err := ev.Verify(&e)

	// Now verify
	assert.Nil(t, err, "unexpected error")
	assert.Len(t, acceptedKeys, 1, "unexpected keys")
	assert.Equal(t, acceptedKeys[0].KeyID, "", "unexpected keyid")

	// Now try an error
	ev, err = NewEnvelopeVerifier(&mockVerifier{returnErr: errors.New("uh oh")})
	assert.Nil(t, err, "unexpected error")
	_, err = ev.Verify(&e)

	// Now verify
	assert.Error(t, err)

}
