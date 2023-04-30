package dsse

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/codahale/rfc6979"
	"github.com/stretchr/testify/assert"
)

var errLength = errors.New("invalid length")

func TestPAE(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		var want = []byte("DSSEv1 0  0 ")

		got := PAE("", []byte{})
		assert.Equal(t, want, got, "Wrong encoding")
	})
	t.Run("Hello world", func(t *testing.T) {
		var want = []byte("DSSEv1 29 http://example.com/HelloWorld 11 hello world")

		got := PAE("http://example.com/HelloWorld", []byte("hello world"))
		assert.Equal(t, want, got, "Wrong encoding")
	})
	t.Run("Unicode-only", func(t *testing.T) {
		var want = []byte("DSSEv1 29 http://example.com/HelloWorld 3 ಠ")

		got := PAE("http://example.com/HelloWorld", []byte("ಠ"))
		assert.Equal(t, want, got, "Wrong encoding")
	})
}

type nilsignerverifier int

func (n nilsignerverifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (n nilsignerverifier) Verify(ctx context.Context, data, sig []byte) error {
	if len(data) != len(sig) {
		return errLength
	}

	for i := range data {
		if data[i] != sig[i] {
			return errVerify
		}
	}

	return nil
}

func (n nilsignerverifier) KeyID() (string, error) {
	return "nil", nil
}

func (n nilsignerverifier) Public() crypto.PublicKey {
	return "nil-public"
}

type nullsignerverifier int

func (n nullsignerverifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (n nullsignerverifier) Verify(ctx context.Context, data, sig []byte) error {
	if len(data) != len(sig) {
		return errLength
	}

	for i := range data {
		if data[i] != sig[i] {
			return errVerify
		}
	}

	return nil
}

func (n nullsignerverifier) KeyID() (string, error) {
	return "null", nil
}

func (n nullsignerverifier) Public() crypto.PublicKey {
	return "null-public"
}

type errsigner int

func (n errsigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("signing error")
}

func (n errsigner) Verify(ctx context.Context, data, sig []byte) error {
	return errVerify
}

func (n errsigner) KeyID() (string, error) {
	return "err", nil
}

func (n errsigner) Public() crypto.PublicKey {
	return "err-public"
}

type errsignerverifier int

var errVerify = fmt.Errorf("accepted signatures do not match threshold, Found: 0, Expected 1")
var errThreshold = fmt.Errorf("invalid threshold")

func (n errsignerverifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (n errsignerverifier) Verify(ctx context.Context, data, sig []byte) error {
	return errVerify
}

func (n errsignerverifier) KeyID() (string, error) {
	return "err", nil
}

func (n errsignerverifier) Public() crypto.PublicKey {
	return "err-public"
}

type badverifier int

func (n badverifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return append(data, byte(0)), nil
}

func (n badverifier) Verify(ctx context.Context, data, sig []byte) error {

	if len(data) != len(sig) {
		return errLength
	}

	for i := range data {
		if data[i] != sig[i] {
			return errVerify
		}
	}

	return nil
}

func (n badverifier) KeyID() (string, error) {
	return "bad", nil
}

func (n badverifier) Public() crypto.PublicKey {
	return "bad-public"
}

func TestNoSigners(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		signer, err := NewEnvelopeSigner(nil)
		assert.Nil(t, signer, "unexpected signer")
		assert.NotNil(t, err, "error expected")
		assert.Equal(t, ErrNoSigners, err, "wrong error")
	})

	t.Run("empty slice", func(t *testing.T) {
		signer, err := NewEnvelopeSigner([]SignerVerifier{}...)
		assert.Nil(t, signer, "unexpected signer")
		assert.NotNil(t, err, "error expected")
		assert.Equal(t, ErrNoSigners, err, "wrong error")
	})
}

func TestNilSign(t *testing.T) {
	var keyID = "nil"
	var payloadType = "http://example.com/HelloWorld"
	var payload = []byte("hello world")

	pae := PAE(payloadType, payload)
	want := Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte(payload)),
		PayloadType: payloadType,
		Signatures: []Signature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(pae),
			},
		},
	}

	var ns nilsignerverifier
	signer, err := NewEnvelopeSigner(ns)
	assert.Nil(t, err, "unexpected error")

	got, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "sign failed")
	assert.Equal(t, &want, got, "bad signature")
}

func TestSignError(t *testing.T) {
	var es errsigner
	signer, err := NewEnvelopeSigner(es)
	assert.Nil(t, err, "unexpected error")

	got, err := signer.SignPayload(context.TODO(), "t", []byte("d"))
	assert.Nil(t, got, "expected nil")
	assert.NotNil(t, err, "error expected")
	assert.Equal(t, "signing error", err.Error(), "wrong error")
}

func newEcdsaKey() *ecdsa.PrivateKey {
	var x big.Int
	var y big.Int
	var d big.Int

	_, ok := x.SetString("46950820868899156662930047687818585632848591499744589407958293238635476079160", 10)
	if !ok {
		return nil
	}
	_, ok = y.SetString("5640078356564379163099075877009565129882514886557779369047442380624545832820", 10)
	if !ok {
		return nil
	}
	_, ok = d.SetString("97358161215184420915383655311931858321456579547487070936769975997791359926199", 10)
	if !ok {
		return nil
	}

	var private = ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     &x,
			Y:     &y,
		},
		D: &d,
	}

	return &private
}

type EcdsaSignerVerifier struct {
	keyID    string
	key      *ecdsa.PrivateKey
	rLen     int
	verified bool
}

func (es *EcdsaSignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	// Data is complete message, hash it and sign the digest
	digest := sha256.Sum256(data)
	r, s, err := rfc6979.SignECDSA(es.key, digest[:], sha256.New)
	if err != nil {
		return nil, err
	}

	rb := r.Bytes()
	sb := s.Bytes()
	es.rLen = len(rb)
	rawSig := append(rb, sb...)

	return rawSig, nil
}

func (es *EcdsaSignerVerifier) Verify(ctx context.Context, data, sig []byte) error {
	var r big.Int
	var s big.Int
	digest := sha256.Sum256(data)
	// Signature here is the raw bytes of r and s concatenated
	rb := sig[:es.rLen]
	sb := sig[es.rLen:]
	r.SetBytes(rb)
	s.SetBytes(sb)

	ok := ecdsa.Verify(&es.key.PublicKey, digest[:], &r, &s)
	es.verified = ok

	if ok {
		return nil
	}
	return errVerify
}

func (es *EcdsaSignerVerifier) KeyID() (string, error) {
	return es.keyID, nil
}

func (es *EcdsaSignerVerifier) Public() crypto.PublicKey {
	return es.key.Public()
}

// Test against the example in the protocol specification:
// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
func TestEcdsaSign(t *testing.T) {
	var keyID = "test key 123"
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"
	var ecdsa = &EcdsaSignerVerifier{
		keyID: keyID,
		key:   newEcdsaKey(),
	}
	var want = Envelope{
		Payload:     "aGVsbG8gd29ybGQ=",
		PayloadType: payloadType,
		Signatures: []Signature{
			{
				KeyID: keyID,
				Sig:   "A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA==",
			},
		},
	}

	signer, err := NewEnvelopeSigner(ecdsa)
	assert.Nil(t, err, "unexpected error")

	env, err := signer.SignPayload(context.TODO(), payloadType, []byte(payload))
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, &want, env, "Wrong envelope generated")

	// Now verify
	verifier, err := NewEnvelopeVerifier(ecdsa)
	assert.Nil(t, err, "unexpected error")
	acceptedKeys, err := verifier.Verify(context.TODO(), env)
	assert.Nil(t, err, "unexpected error")
	assert.True(t, ecdsa.verified, "verify was not called")
	assert.Len(t, acceptedKeys, 1, "unexpected keys")
	assert.Equal(t, acceptedKeys[0].KeyID, keyID, "unexpected keyid")
}

func TestDecodeB64Payload(t *testing.T) {
	var want = make([]byte, 256)
	for i := range want {
		want[i] = byte(i)
	}
	var b64Url = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w=="
	var b64Std = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w=="
	var b64UrlErr = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w"
	var b64StdErr = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w"

	t.Run("Standard encoding", func(t *testing.T) {
		env := &Envelope{
			Payload: b64Std,
		}
		got, err := env.DecodeB64Payload()
		assert.Nil(t, err, "unexpected error")
		assert.Equal(t, want, got, "wrong data")
	})
	t.Run("URL encoding", func(t *testing.T) {
		env := &Envelope{
			Payload: b64Url,
		}
		got, err := env.DecodeB64Payload()
		assert.Nil(t, err, "unexpected error")
		assert.Equal(t, want, got, "wrong data")
	})

	t.Run("Standard encoding - error", func(t *testing.T) {
		env := &Envelope{
			Payload: b64StdErr,
		}
		got, err := env.DecodeB64Payload()
		assert.NotNil(t, err, "expected error")
		assert.Nil(t, got, "wrong data")
	})
	t.Run("URL encoding - error", func(t *testing.T) {
		env := &Envelope{
			Payload: b64UrlErr,
		}
		got, err := env.DecodeB64Payload()
		assert.NotNil(t, err, "expected error")
		assert.Nil(t, got, "wrong data")
	})
}

func TestVerifyOneProvider(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var ns nilsignerverifier
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

	var ns nilsignerverifier
	var null nullsignerverifier
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

	var ns nilsignerverifier
	var null nullsignerverifier
	signer, err := NewMultiEnvelopeSigner(2, ns, null)
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
	var ns nilsignerverifier
	var null nullsignerverifier
	_, err := NewMultiEnvelopeVerifier(3, ns, null)
	assert.Equal(t, errThreshold, err, "wrong error")
	_, err = NewMultiEnvelopeVerifier(0, ns, null)
	assert.Equal(t, errThreshold, err, "wrong error")
}

func TestVerifyErr(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var errsv errsignerverifier
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

	t.Run("Payload", func(t *testing.T) {
		env := &Envelope{
			Payload: "Not base 64",
			Signatures: []Signature{
				{},
			},
		}

		_, err := verifier.Verify(context.TODO(), env)
		assert.IsType(t, base64.CorruptInputError(0), err, "wrong error")
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
		assert.IsType(t, base64.CorruptInputError(0), err, "wrong error")
	})
}

func TestVerifyNoMatch(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"

	var ns nilsignerverifier
	var null nullsignerverifier
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

type interceptSigner struct {
	keyID        string
	verifyRes    bool
	verifyCalled bool
}

func (i *interceptSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (i *interceptSigner) Verify(ctx context.Context, data, sig []byte) error {
	i.verifyCalled = true

	if i.verifyRes {
		return nil
	}
	return errVerify
}

func (i *interceptSigner) KeyID() (string, error) {
	return i.keyID, nil
}

func (i *interceptSigner) Public() crypto.PublicKey {
	return "intercept-public"
}

func TestVerifyOneFail(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"

	var s1 = &interceptSigner{
		keyID:     "i1",
		verifyRes: true,
	}
	var s2 = &interceptSigner{
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

	var s1 = &interceptSigner{
		keyID:     "i1",
		verifyRes: true,
	}
	var s2 = &interceptSigner{
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

	var s1 = &interceptSigner{
		keyID:     "",
		verifyRes: true,
	}

	var s2 = &interceptSigner{
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
	// assert.True(t, s1.verifyCalled, "verify not called")
	// assert.True(t, s2.verifyCalled, "verify not called")
	assert.Len(t, acceptedKeys, 1, "unexpected keys")
	assert.Equal(t, acceptedKeys[0].KeyID, "", "unexpected keyid")
}

func TestVerifyPublicKeyID(t *testing.T) {
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"
	var keyID = "SHA256:f4AuBLdH4Lj/dIuwAUXXebzoI9B/cJ4iSQ3/qByIl4M"
	// var keyID = "test key 123"

	var s1 = &EcdsaSignerVerifier{
		keyID: "",
		key:   newEcdsaKey(),
	}

	var s2 = &EcdsaSignerVerifier{
		keyID: "",
		key:   newEcdsaKey(),
	}
	// a := s1.Public()

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
