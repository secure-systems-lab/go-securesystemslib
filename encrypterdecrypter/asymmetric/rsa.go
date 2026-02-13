package asymmetric

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	sv "github.com/secure-systems-lab/go-securesystemslib/signerverifier"
)

type RSAEncrypterDecrypter struct {
	keyID   string
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

func NewRSAEncrypterDecrypterFromSSLibKey(key *sv.SSLibKey) (*RSAEncrypterDecrypter, error) {
	if len(key.KeyVal.Public) == 0 {
		return nil, sv.ErrInvalidKey
	}

	_, publicParsedKey, err := sv.DecodeAndParsePEM([]byte(key.KeyVal.Public))
	if err != nil {
		return nil, fmt.Errorf("unable to create RSA encrypterdecrypter: %w", err)
	}

	if len(key.KeyVal.Private) > 0 {
		_, privateParsedKey, err := sv.DecodeAndParsePEM([]byte(key.KeyVal.Private))
		if err != nil {
			return nil, fmt.Errorf("unable to create RSA encrypterdecrypter: %w", err)
		}

		return &RSAEncrypterDecrypter{
			keyID:   key.KeyID,
			public:  publicParsedKey.(*rsa.PublicKey),
			private: privateParsedKey.(*rsa.PrivateKey),
		}, nil
	}

	return &RSAEncrypterDecrypter{
		keyID:   key.KeyID,
		public:  publicParsedKey.(*rsa.PublicKey),
		private: nil,
	}, nil
}

// Encrypt encrypts the provided data with the public key of the RSA
// EncrypterDecrypter instance.
func (ed *RSAEncrypterDecrypter) Encrypt(data []byte) ([]byte, error) {
	rng := rand.Reader
	return rsa.EncryptOAEP(sha256.New(), rng, ed.public, data, nil)
}

// Decrypt decrypts the provided data with the private key of the RSA
// EncrypterDecrypter instance.
func (ed *RSAEncrypterDecrypter) Decrypt(data []byte) ([]byte, error) {
	if ed.private == nil {
		return nil, sv.ErrNotPrivateKey
	}

	return rsa.DecryptOAEP(sha256.New(), nil, ed.private, data, nil)
}

// KeyID returns the key ID of the key used to create the RSA EncrypterDecrypter
// instance.
func (ed *RSAEncrypterDecrypter) KeyID() (string, error) {
	return ed.keyID, nil
}
