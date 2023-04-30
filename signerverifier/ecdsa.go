package signerverifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"os"
)

const ECDSAKeyType = "ecdsa"

type ECDSASignerVerifier struct {
	keyID     string
	curveSize int
	private   *ecdsa.PrivateKey
	public    *ecdsa.PublicKey
}

func NewECDSASignerVerifierFromSSLibKey(key *SSLibKey) (*ECDSASignerVerifier, error) {
	_, publicParsedKey, err := decodeAndParsePEM([]byte(key.KeyVal.Public))
	if err != nil {
		return nil, err
	}

	sv := &ECDSASignerVerifier{
		keyID:     key.KeyID(),
		curveSize: publicParsedKey.(*ecdsa.PublicKey).Params().BitSize,
		public:    publicParsedKey.(*ecdsa.PublicKey),
		private:   nil,
	}

	if len(key.KeyVal.Private) > 0 {
		_, privateParsedKey, err := decodeAndParsePEM([]byte(key.KeyVal.Private))
		if err != nil {
			return nil, err
		}

		sv.private = privateParsedKey.(*ecdsa.PrivateKey)
	}

	return sv, nil
}

func (sv *ECDSASignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	if sv.private == nil {
		return nil, ErrNotPrivateKey
	}

	hashedData := getECDSAHashedData(data, sv.curveSize)

	return ecdsa.SignASN1(rand.Reader, sv.private, hashedData)
}

func (sv *ECDSASignerVerifier) Verify(ctx context.Context, data []byte, sig []byte) error {
	hashedData := getECDSAHashedData(data, sv.curveSize)

	if ok := ecdsa.VerifyASN1(sv.public, hashedData, sig); !ok {
		return ErrSignatureVerificationFailed
	}

	return nil
}

func (sv *ECDSASignerVerifier) KeyID() (string, error) {
	return sv.keyID, nil
}

func (sv *ECDSASignerVerifier) Public() crypto.PublicKey {
	return sv.public
}

func LoadECDSAKeyFromFile(path string) (*SSLibKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return loadKeyFromSSLibBytes(contents)
}

func getECDSAHashedData(data []byte, curveSize int) []byte {
	switch {
	case curveSize <= 256:
		return hashBeforeSigning(data, sha256.New())
	case 256 < curveSize && curveSize <= 384:
		return hashBeforeSigning(data, sha512.New384())
	case curveSize > 384:
		return hashBeforeSigning(data, sha512.New())
	}
	return []byte{}
}
