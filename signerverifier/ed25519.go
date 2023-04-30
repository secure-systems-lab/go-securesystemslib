package signerverifier

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"os"
)

const Ed25519KeyType = "ed25519"

type Ed25519SignerVerifier struct {
	keyID   string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

// NewEd25519SignerVerifierFromSSLibKey creates an Ed25519SignerVerifier from an
// SSLibKey.
func NewEd25519SignerVerifierFromSSLibKey(key *SSLibKey) (*Ed25519SignerVerifier, error) {
	public, err := hex.DecodeString(key.KeyVal.Public)
	if err != nil {
		return nil, err
	}

	var private []byte
	if len(key.KeyVal.Private) > 0 {
		private, err = hex.DecodeString(key.KeyVal.Private)
		if err != nil {
			return nil, err
		}

		// python-securesystemslib provides an interface to generate ed25519
		// keys but it differs slightly in how it serializes the key to disk.
		// Specifically, the keyval.private field includes _only_ the private
		// portion of the key while libraries such as crypto/ed25519 also expect
		// the public portion. So, if the private portion is half of what we
		// expect, we append the public portion as well.
		if len(private) == ed25519.PrivateKeySize/2 {
			private = append(private, public...)
		}
	}

	return &Ed25519SignerVerifier{
		keyID:   key.KeyID(),
		public:  ed25519.PublicKey(public),
		private: ed25519.PrivateKey(private),
	}, nil
}

// Sign creates a signature for `data`.
func (sv *Ed25519SignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	if len(sv.private) == 0 {
		return nil, ErrNotPrivateKey
	}

	signature := ed25519.Sign(sv.private, data)
	return signature, nil
}

// Verify verifies the `sig` value passed in against `data`.
func (sv Ed25519SignerVerifier) Verify(ctx context.Context, data []byte, sig []byte) error {
	if ok := ed25519.Verify(sv.public, data, sig); ok {
		return nil
	}
	return ErrSignatureVerificationFailed
}

// KeyID returns the identifier of the key used to create the
// Ed25519SignerVerifier instance.
func (sv Ed25519SignerVerifier) KeyID() (string, error) {
	return sv.keyID, nil
}

// Public returns the public portion of the key used to create the
// Ed25519SignerVerifier instance.
func (sv Ed25519SignerVerifier) Public() crypto.PublicKey {
	return sv.public
}

func LoadEd25519KeyFromFile(path string) (*SSLibKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return loadKeyFromSSLibBytes(contents)
}
