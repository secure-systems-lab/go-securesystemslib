package encrypterdecrypter

// Encrypter is the interface for an abstract asymmetric or symmetric block
// encryption algorithm. The Encrypter interface is used to encrypt arbitrary
// byte payloads, and returns the ciphertext, or an error. It is
// cipher-agnostic.
type Encrypter interface {
	Encrypt([]byte) ([]byte, error)
	KeyID() (string, error)
}

// Decrypter is the interface to decrypt ciphertext.
type Decrypter interface {
	Decrypt([]byte) ([]byte, error)
	KeyID() (string, error)
}

// EncrypterDecrypter is the combined interface of Encrypter and Decrypter.
type EncrypterDecrypter interface {
	Encrypter
	Decrypter
}
