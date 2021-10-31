package dsse

import (
	"crypto"
	"errors"
	"fmt"
)

/*
Verifier verifies a complete message against a signature and key.
If the message was hashed prior to signature generation, the verifier
must perform the same steps.
If Keyd returns successfully only signiture matching keyid will be verfied.
*/
type Verifier interface {
	Verify(data, sig []byte) error
	KeyID() (string, error)
	Public() crypto.PublicKey
}

type envelopeMultiVerifier struct {
	providers []Verifier
	threshold int
}

type AccesptedKey struct {
	Public crypto.PublicKey
	KeyID  string
	Sig    Signature
}

func (ev *envelopeMultiVerifier) Verify(e *Envelope) ([]AccesptedKey, error) {
	if len(e.Signatures) == 0 {
		return nil, ErrNoSignature
	}

	// Decode payload (i.e serialized body)
	body, err := b64Decode(e.Payload)
	if err != nil {
		return nil, err
	}
	// Generate PAE(payloadtype, serialized body)
	paeEnc := PAE(e.PayloadType, string(body))

	// If *any* signature is found to be incorrect, it is skipped
	var accepted_keys []AccesptedKey
	for _, s := range e.Signatures {
		sig, err := b64Decode(s.Sig)
		if err != nil {
			return nil, err
		}

		// Loop over the providers.
		// If provider and signiture include keyID's but do not match skip.
		// If a provider recognizes the key, we exit
		// the loop and use the result.
		for _, v := range ev.providers {
			keyID, err := v.KeyID()
			if s.KeyID != "" && keyID != "" && err == nil && s.KeyID != keyID {
				continue
			}
			if err != nil {
				keyID = ""
			}

			err = v.Verify(paeEnc, sig)
			if err != nil {
				continue
			}

			acceptedKey := AccesptedKey{
				Public: v.Public(),
				KeyID:  keyID,
				Sig:    s,
			}

			accepted_keys = append(accepted_keys, acceptedKey)
			break
		}
	}
	if len(accepted_keys) < ev.threshold {
		return accepted_keys, errors.New(fmt.Sprintf("Accepted signitures do not match threshold, Found: %d, Expected %d", len(accepted_keys), ev.threshold))
	}

	return accepted_keys, nil
}

func NewEnvelopeVerifier(v ...Verifier) (*envelopeMultiVerifier, error) {
	return NewMultiEnvelopeVerifier(1, v...)
}

func NewMultiEnvelopeVerifier(threshold int, p ...Verifier) (*envelopeMultiVerifier, error) {

	if threshold <= 0 || threshold > len(p) {
		return nil, errors.New("Invalid threshold")
	}

	ev := envelopeMultiVerifier{
		providers: p,
		threshold: threshold,
	}
	return &ev, nil
}
