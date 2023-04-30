package signerverifier

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
)

// ErrNoPEMBlock gets triggered when there is no PEM block in the provided file
var ErrNoPEMBlock = errors.New("failed to decode the data as PEM block (are you sure this is a pem file?)")

// ErrFailedPEMParsing gets returned when PKCS1, PKCS8 or PKIX key parsing fails
var ErrFailedPEMParsing = errors.New("failed parsing the PEM block: unsupported PEM type")

const (
	RSAKeyType       = "rsa"
	RSAKeyScheme     = "rsassa-pss-sha256"
	RSAPublicKeyPEM  = "PUBLIC KEY"
	RSAPrivateKeyPEM = "RSA PRIVATE KEY"
)

type RSAPSSSignerVerifier struct {
	keyID   string
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

func NewRSAPSSSignerVerifierFromSSLibKey(key *SSLibKey) (*RSAPSSSignerVerifier, error) {
	_, publicParsedKey, err := decodeAndParsePEM([]byte(key.KeyVal.Public))
	if err != nil {
		return nil, err
	}

	if len(key.KeyVal.Private) > 0 {
		_, privateParsedKey, err := decodeAndParsePEM([]byte(key.KeyVal.Private))
		if err != nil {
			return nil, err
		}

		return &RSAPSSSignerVerifier{
			keyID:   key.KeyID(),
			public:  publicParsedKey.(*rsa.PublicKey),
			private: privateParsedKey.(*rsa.PrivateKey),
		}, nil
	}

	return &RSAPSSSignerVerifier{
		keyID:   key.KeyID(),
		public:  publicParsedKey.(*rsa.PublicKey),
		private: nil,
	}, nil
}

func (sv *RSAPSSSignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	if sv.private == nil {
		return nil, ErrNotPrivateKey
	}

	hashedData := hashBeforeSigning(data)

	return rsa.SignPSS(rand.Reader, sv.private, crypto.SHA256, hashedData, &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})
}

func (sv RSAPSSSignerVerifier) Verify(ctx context.Context, data []byte, sig []byte) error {
	hashedData := hashBeforeSigning(data)

	if err := rsa.VerifyPSS(sv.public, crypto.SHA256, hashedData, sig, &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256}); err != nil {
		return ErrSignatureVerificationFailed
	}

	return nil
}

func (sv RSAPSSSignerVerifier) KeyID() (string, error) {
	return sv.keyID, nil
}

func (sv RSAPSSSignerVerifier) Public() crypto.PublicKey {
	return sv.public
}

func LoadRSAPSSKeyFromFile(path string) (*SSLibKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemData, keyObj, err := decodeAndParsePEM(contents)
	if err != nil {
		return nil, err
	}

	key := &SSLibKey{
		KeyType:             RSAKeyType,
		Scheme:              RSAKeyScheme,
		KeyIDHashAlgorithms: KeyIDHashAlgorithms,
		KeyVal:              KeyVal{},
	}

	switch k := keyObj.(type) {
	case *rsa.PublicKey:
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		key.KeyVal.Public = string(generatePEMBlock(pubKeyBytes, RSAPublicKeyPEM))

	case *rsa.PrivateKey:
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			return nil, err
		}
		key.KeyVal.Public = string(generatePEMBlock(pubKeyBytes, RSAPublicKeyPEM))
		key.KeyVal.Private = string(generatePEMBlock(pemData.Bytes, RSAPrivateKeyPEM))
	}

	keyID, err := calculateKeyID(key)
	if err != nil {
		return nil, err
	}
	key.keyID = keyID

	return key, nil
}
