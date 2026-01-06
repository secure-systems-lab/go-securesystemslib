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

type nilSignerVerifier int

func (n nilSignerVerifier) Sign(_ context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (n nilSignerVerifier) Verify(_ context.Context, data, sig []byte) error {
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

func (n nilSignerVerifier) KeyID() (string, error) {
	return "nil", nil
}

func (n nilSignerVerifier) Public() crypto.PublicKey {
	return "nil-public"
}

type nullSignerVerifier int

func (n nullSignerVerifier) Sign(_ context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (n nullSignerVerifier) Verify(_ context.Context, data, sig []byte) error {
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

func (n nullSignerVerifier) KeyID() (string, error) {
	return "null", nil
}

func (n nullSignerVerifier) Public() crypto.PublicKey {
	return "null-public"
}

type errsigner int

func (n errsigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("signing error")
}

func (n errsigner) Verify(_ context.Context, _, _ []byte) error {
	return errVerify
}

func (n errsigner) KeyID() (string, error) {
	return "err", nil
}

func (n errsigner) Public() crypto.PublicKey {
	return "err-public"
}

type errSignerVerifier int

var errVerify = fmt.Errorf("accepted signatures do not match threshold, Found: 0, Expected 1")
var errThreshold = fmt.Errorf("invalid threshold")

func (n errSignerVerifier) Sign(_ context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (n errSignerVerifier) Verify(_ context.Context, _, _ []byte) error {
	return errVerify
}

func (n errSignerVerifier) KeyID() (string, error) {
	return "err", nil
}

func (n errSignerVerifier) Public() crypto.PublicKey {
	return "err-public"
}

type badverifier int

func (n badverifier) Sign(_ context.Context, data []byte) ([]byte, error) {
	return append(data, byte(0)), nil
}

func (n badverifier) Verify(_ context.Context, data, sig []byte) error {
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
		signer, err := NewEnvelopeSigner([]Signer{}...)
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
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: payloadType,
		Signatures: []Signature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(pae),
			},
		},
	}

	var ns nilSignerVerifier
	signer, err := NewEnvelopeSigner(ns)
	assert.Nil(t, err, "unexpected error")

	got, err := signer.SignPayload(context.TODO(), payloadType, payload)
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

type ecdsaSignerVerifier struct {
	keyID    string
	key      *ecdsa.PrivateKey
	rLen     int
	verified bool
}

func (es *ecdsaSignerVerifier) Sign(_ context.Context, data []byte) ([]byte, error) {
	// Data is complete message, hash it and sign the digest
	digest := sha256.Sum256(data)
	r, s, err := rfc6979.SignECDSA(es.key, digest[:], sha256.New)
	if err != nil {
		return nil, err
	}

	rb := r.Bytes()
	sb := s.Bytes()
	es.rLen = len(rb)
	rawSig := append(rb, sb...) //nolint:gocritic

	return rawSig, nil
}

func (es *ecdsaSignerVerifier) Verify(_ context.Context, data, sig []byte) error {
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

func (es *ecdsaSignerVerifier) KeyID() (string, error) {
	return es.keyID, nil
}

func (es *ecdsaSignerVerifier) Public() crypto.PublicKey {
	return es.key.Public()
}

// Test against the example in the protocol specification:
// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
func TestEcdsaSign(t *testing.T) {
	var keyID = "test key 123"
	var payloadType = "http://example.com/HelloWorld"
	var payload = "hello world"
	var ecdsa = &ecdsaSignerVerifier{
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
