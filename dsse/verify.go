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

type envelopeVerifier struct {
	providers []Verifier
	threshold int
}

type AcceptedKeys struct {
	Public crypto.PublicKey
	KeyID  string
	Sig    Signature
}

func (ev *envelopeVerifier) Verify(e *Envelope) ([]AcceptedKeys, error) {
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
	var acceptedKeys []AcceptedKeys
	usedKeyids := make(map[string]string)
	for _, s := range e.Signatures {
		sig, err := b64Decode(s.Sig)
		if err != nil {
			return nil, err
		}

		// Loop over the providers.
		// If provider and signature include key IDs but do not match skip.
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

			acceptedKey := AcceptedKeys{
				Public: v.Public(),
				KeyID:  keyID,
				Sig:    s,
			}

			// See https://github.com/in-toto/in-toto/pull/251
			if val, ok := usedKeyids[keyID]; ok {
				fmt.Printf("Found envelope signed by different subkeys of the same main key, Only one of them is counted towards the step threshold, KeyID=%s\n", val)
			}

			usedKeyids[keyID] = ""
			acceptedKeys = append(acceptedKeys, acceptedKey)
			break
		}
	}

	// Sanity if with some reflect magic this happens.
	if ev.threshold <= 0 || ev.threshold > len(ev.providers) {
		return nil, errors.New("Invalid threshold")
	}

	if len(usedKeyids) < ev.threshold {
		return acceptedKeys, errors.New(fmt.Sprintf("Accepted signitures do not match threshold, Found: %d, Expected %d", len(acceptedKeys), ev.threshold))
	}

	return acceptedKeys, nil
}

func NewEnvelopeVerifier(v ...Verifier) (*envelopeVerifier, error) {
	return NewMultiEnvelopeVerifier(1, v...)
}

func NewMultiEnvelopeVerifier(threshold int, p ...Verifier) (*envelopeVerifier, error) {

	if threshold <= 0 || threshold > len(p) {
		return nil, errors.New("Invalid threshold")
	}

	ev := envelopeVerifier{
		providers: p,
		threshold: threshold,
	}
	return &ev, nil
}
